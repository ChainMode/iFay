import { canonicalizeJcs, createFayManifest, validateFayManifest, verifyEd25519 } from '@ifay/sdk';
import { packBufBinary, parseBufBinary } from './buf-codec.mjs';
import { THOUGHT_SUBTYPES, validateIfayProfile } from './ifay-profile.mjs';

export const DEVICE_PROFILE_SCHEMA_VERSION = 'fayger-device-profile/1.0';
export const REMOTE_POINTER_SCHEMA_VERSION = 'ifay-remote-pointer/1.0';
export const REMOTE_POINTER_SIGNING_DOMAIN = 'ifay.soul.remote-primary-pointer.v1';

export const DEVICE_TIERS = Object.freeze(['super', 'plus', 'normal', 'lite', 'thin']);

export const OFFICIAL_DEVICE_PROFILES = Object.freeze({
  super: {
    schema_version: DEVICE_PROFILE_SCHEMA_VERSION,
    device_id: 'dev-workstation-super',
    platform_id: 'native-desktop',
    tier: 'super',
    memory_mb: 32768,
    free_storage_mb: 131072,
    network_online: true,
    remote_only: false,
    granted_capabilities: [
      'fs.read',
      'fs.write',
      'net.http',
      'ui.dom',
      'time.now',
      'random.bytes',
      'crypto.hash',
      'proc.spawn',
      'host.call',
    ],
  },
  plus: {
    schema_version: DEVICE_PROFILE_SCHEMA_VERSION,
    device_id: 'dev-laptop-plus',
    platform_id: 'native-desktop',
    tier: 'plus',
    memory_mb: 16384,
    free_storage_mb: 32768,
    network_online: true,
    remote_only: false,
    granted_capabilities: ['fs.read', 'fs.write', 'net.http', 'time.now', 'crypto.hash', 'host.call'],
  },
  normal: {
    schema_version: DEVICE_PROFILE_SCHEMA_VERSION,
    device_id: 'dev-mobile-normal',
    platform_id: 'in-app',
    tier: 'normal',
    memory_mb: 2048,
    free_storage_mb: 2048,
    network_online: true,
    remote_only: false,
    granted_capabilities: ['fs.read', 'net.http', 'time.now', 'crypto.hash'],
  },
  lite: {
    schema_version: DEVICE_PROFILE_SCHEMA_VERSION,
    device_id: 'dev-drone-lite',
    platform_id: 'embedded-edge',
    tier: 'lite',
    memory_mb: 512,
    free_storage_mb: 256,
    network_online: false,
    remote_only: false,
    granted_capabilities: ['fs.read', 'crypto.hash', 'host.call'],
    preferred_domains: ['aerial_photography', 'navigation'],
    ego_slot: 'casual',
  },
  thin: {
    schema_version: DEVICE_PROFILE_SCHEMA_VERSION,
    device_id: 'dev-watch-thin',
    platform_id: 'in-app',
    tier: 'thin',
    memory_mb: 64,
    free_storage_mb: 8,
    network_online: true,
    remote_only: true,
    granted_capabilities: ['net.http', 'time.now'],
    primary_body_endpoint: 'https://primary.ifay.local/rpc/v1',
  },
});

export function normalizeDeviceRuntimeProfile(input = {}) {
  const tierHint = input.tier ?? inferTierFromResources(input);
  if (!DEVICE_TIERS.includes(tierHint)) {
    throw new Error(`Invalid DeviceRuntimeProfile tier '${String(tierHint)}'`);
  }
  const preset = OFFICIAL_DEVICE_PROFILES[tierHint];
  const memoryMb = Number.isFinite(input.memory_mb) ? input.memory_mb : preset.memory_mb;
  const freeStorageMb = Number.isFinite(input.free_storage_mb)
    ? input.free_storage_mb
    : preset.free_storage_mb;
  const networkOnline =
    typeof input.network_online === 'boolean' ? input.network_online : preset.network_online;
  const remoteOnly =
    input.remote_only === true ||
    tierHint === 'thin' ||
    ((memoryMb < 128 || freeStorageMb < 16) && networkOnline);

  return {
    schema_version: input.schema_version ?? DEVICE_PROFILE_SCHEMA_VERSION,
    device_id: String(input.device_id ?? preset.device_id),
    platform_id: String(input.platform_id ?? preset.platform_id),
    tier: remoteOnly ? 'thin' : tierHint,
    memory_mb: memoryMb,
    free_storage_mb: freeStorageMb,
    network_online: networkOnline,
    remote_only: remoteOnly,
    granted_capabilities: Array.from(
      new Set(input.granted_capabilities ?? preset.granted_capabilities ?? []),
    ),
    preferred_domains: Array.from(
      new Set(input.preferred_domains ?? preset.preferred_domains ?? []),
    ),
    ego_slot: input.ego_slot ?? preset.ego_slot ?? null,
    primary_body_endpoint:
      input.primary_body_endpoint ?? preset.primary_body_endpoint ?? 'fay://primary-body/default',
  };
}

function inferTierFromResources(input) {
  if (input.remote_only === true) return 'thin';
  const mem = input.memory_mb ?? 16384;
  const storage = input.free_storage_mb ?? 32768;
  if (mem < 128 || storage < 16) return 'thin';
  if (mem <= 768 || storage <= 512) return 'lite';
  if (mem <= 4096 || storage <= 4096) return 'normal';
  if (mem < 24576) return 'plus';
  return 'super';
}

export function signRemotePrimaryPointer(pointerCore, signer) {
  const preimage = Buffer.from(
    `${REMOTE_POINTER_SIGNING_DOMAIN}\0${canonicalizeJcs(pointerCore)}`,
    'utf8',
  );
  const sigHex = signer.signPayload(preimage).toString('hex');
  return {
    ...pointerCore,
    signature: {
      alg: 'Ed25519',
      domain: REMOTE_POINTER_SIGNING_DOMAIN,
      public_key_hex: signer.publicKeyHex,
      signature_hex: sigHex,
    },
  };
}

export function verifyRemotePrimaryPointer(pointer, trustedPublicKeyHex) {
  if (!pointer || pointer.schema_version !== REMOTE_POINTER_SCHEMA_VERSION) return false;
  const sig = pointer.signature;
  if (!sig || sig.alg !== 'Ed25519' || sig.domain !== REMOTE_POINTER_SIGNING_DOMAIN) return false;
  const pubHex = trustedPublicKeyHex ?? sig.public_key_hex;
  if (!pubHex || pubHex !== sig.public_key_hex) return false;
  const core = { ...pointer };
  delete core.signature;
  const preimage = Buffer.from(
    `${REMOTE_POINTER_SIGNING_DOMAIN}\0${canonicalizeJcs(core)}`,
    'utf8',
  );
  return verifyEd25519(pubHex, preimage, sig.signature_hex);
}

function selectActivePersona(fullProfile, requestedEgoSlot) {
  const targetId = requestedEgoSlot ?? fullProfile.ego.active_persona_id;
  const found = fullProfile.ego.personas.find((p) => p.persona_id === targetId);
  const chosenId = found ? targetId : fullProfile.ego.active_persona_id;
  return fullProfile.ego.personas.map((p) => ({
    ...structuredClone(p),
    active: p.persona_id === chosenId,
  }));
}

function computeQuotasForDevice(device) {
  const memCapBytes = Math.max(16, Math.floor(device.memory_mb * 0.5)) * 1024 * 1024;
  const cpuMap = { super: 900, plus: 700, normal: 400, lite: 200, thin: 50 };
  const ioMap = {
    super: 200 * 1024 * 1024,
    plus: 100 * 1024 * 1024,
    normal: 25 * 1024 * 1024,
    lite: 5 * 1024 * 1024,
    thin: 1 * 1024 * 1024,
  };
  return {
    cpu_ms_per_sec: cpuMap[device.tier] ?? 300,
    memory_bytes: memCapBytes,
    io_bytes_per_sec: ioMap[device.tier] ?? 10 * 1024 * 1024,
  };
}

/**
 * Dynamically slices an iFay Primary Body for a target FayGer DeviceRuntimeProfile
 * and packages a 100% FayGer-compatible BUF\0 v1 binary artifact.
 */
export function sliceSoulForDevice(primaryBody, rawDeviceProfile = {}, options = {}) {
  const device = normalizeDeviceRuntimeProfile(rawDeviceProfile);
  const fullProfile = primaryBody.profile;

  if (device.remote_only && !device.network_online) {
    throw new Error(
      'DEVICE_PROFILE_INFEASIBLE: remote_only terminal requires network_online=true to reach Primary Body',
    );
  }

  const adjustedPersonas = selectActivePersona(fullProfile, device.ego_slot);
  const activePersona = adjustedPersonas.find((p) => p.active === true);
  const grantedSet = new Set(device.granted_capabilities);

  // Requested capabilities of the soul vs Host granted_capabilities (2-layer capability intersection)
  const requestedCaps = Array.from(
    new Set(['fs.read', 'crypto.hash', ...fullProfile.skill.flatMap((s) => s.required_capabilities)]),
  );
  const effectiveCapabilities = requestedCaps.filter((c) => grantedSet.has(c));

  const quotas = computeQuotasForDevice(device);
  const bufSigner = options.signBuf === false ? null : primaryBody.getBufSigner?.() ?? null;

  const syncAnchor = {
    schema_version: 'ifay-sync-anchor/1.0',
    soul_fay_id: primaryBody.fayId,
    origin_replica_id: primaryBody.replicaId,
    genesis_hash: primaryBody.genesisHash,
    head_hashes: primaryBody.headHashes,
    state_root_sha256: primaryBody.stateRootSha256,
    commit_back_endpoint: device.primary_body_endpoint,
    target_device_id: device.device_id,
  };

  // ==========================================================================
  // Mode 3: Ultra-Thin / remote_only Terminal (Zero Heavy Local Thought / Ego)
  // ==========================================================================
  if (device.remote_only || device.tier === 'thin') {
    const pointerSigner = primaryBody.signer ?? primaryBody.humanPrimeSigner;
    if (!pointerSigner) {
      throw new Error('RemotePrimaryPointer slicing requires an active Ed25519 signer on PrimaryBodyStore');
    }

    const thinProfile = {
      schema_version: fullProfile.schema_version,
      identity: structuredClone(fullProfile.identity),
      ego: {
        active_persona_id: activePersona.persona_id,
        personas: [
          {
            persona_id: activePersona.persona_id,
            label: activePersona.label,
            active: true,
            model_source: 'remote://primary-body/ego-three-in-one',
            compact_slice_ref: 'remote://none',
            edition_version: activePersona.edition_version,
            scenario_tags: activePersona.scenario_tags,
            style_traits: activePersona.style_traits,
            redlines: activePersona.redlines,
            bound_fay_id: fullProfile.identity.fay_id,
          },
        ],
        human_corrections: [],
      },
      thought: { content: [], data: [], knowledge_base: [], info_feed: [] },
      skill: [],
      hardware: { device: [], storage: [], computing: [] },
      permissions: {
        inherent: ['preferences.read'],
        persistent: [],
        ephemeral: effectiveCapabilities,
        auth_methods: ['fayid_ed25519'],
      },
    };

    const profileCheck = validateIfayProfile(thinProfile);
    if (!profileCheck.valid) {
      throw new Error(`Thin profile invalid: ${profileCheck.errors.join(', ')}`);
    }

    const signedPointer = signRemotePrimaryPointer(
      {
        schema_version: REMOTE_POINTER_SCHEMA_VERSION,
        soul_fay_id: primaryBody.fayId,
        active_persona_id: activePersona.persona_id,
        primary_endpoint: device.primary_body_endpoint,
        commit_back_endpoint: `${device.primary_body_endpoint}/commit-delta`,
        ledger_head_hashes: primaryBody.headHashes,
        state_root_sha256: primaryBody.stateRootSha256,
        target_device_id: device.device_id,
        negotiated_capabilities: effectiveCapabilities,
        local_thought_items: 0,
        local_ego_weights_bundled: false,
        issued_at: options.issuedAt ?? '2026-11-20T00:00:00.000Z',
      },
      pointerSigner,
    );

    const fayManifest = createFayManifest({
      name: `${fullProfile.identity.fay_id.slice(0, 14)}-thin-pointer`,
      version: '1.0.0',
      description: `Ultra-thin remote-primary embodiment pointer for ${device.device_id}`,
      vendor: 'HumanPrime Self-Sovereign',
      fayId: primaryBody.fayId,
      controlMode: 'command',
      modules: [{ id: 'invoke_skill', version: '^1.0.0' }],
      protocols: [
        { id: 'faying_protocol', version: '^1.0.0' },
        { id: 'icp_protocol', version: '^1.0.0' },
      ],
      permissions: {
        inherent: thinProfile.permissions.inherent,
        persistent: [],
        authMethods: ['fayid_ed25519'],
      },
    });
    const manifestCheck = validateFayManifest(fayManifest);
    if (!manifestCheck.valid) {
      throw new Error(`Thin FayManifest invalid: ${manifestCheck.errors.join('; ')}`);
    }

    const taskIr = {
      schema_version: 'fayger-task-ir/1.0',
      embodiment_mode: 'remote_primary_pointer',
      soul_fay_id: primaryBody.fayId,
      target_device_id: device.device_id,
      remote_endpoint: device.primary_body_endpoint,
      steps: [],
    };

    const bufSpec = {
      schemaVersion: '1.0.0',
      runtimeInterfaceMin: '1.0.0',
      entry: 'main',
      capabilities: effectiveCapabilities,
      quotas,
      extensions: {
        fay_entity_kind: 'ifay',
        fay_id: primaryBody.fayId,
        embodiment_mode: 'remote_primary_pointer',
        device_tier: device.tier,
        state_root_sha256: primaryBody.stateRootSha256,
      },
      sections: [
        {
          id: 'code',
          kind: 'code',
          visibility: 'required',
          payload: Buffer.from(canonicalizeJcs(taskIr), 'utf8'),
        },
        {
          id: 'fay_manifest',
          kind: 'data',
          visibility: 'required',
          payload: Buffer.from(canonicalizeJcs(fayManifest), 'utf8'),
        },
        {
          id: 'soul_profile',
          kind: 'data',
          visibility: 'required',
          payload: Buffer.from(canonicalizeJcs(thinProfile), 'utf8'),
        },
        {
          id: 'remote_primary_pointer',
          kind: 'data',
          visibility: 'required',
          payload: Buffer.from(canonicalizeJcs(signedPointer), 'utf8'),
        },
      ],
      ...(bufSigner ? { signer: bufSigner } : {}),
    };

    const bufBytes = packBufBinary(bufSpec);
    const parsedBuf = parseBufBinary(bufBytes, {
      ...(bufSigner ? { trustedPublicKeyHex: bufSigner.publicKeyHex } : {}),
    });

    return {
      mode: 'remote_primary_pointer',
      tier: device.tier,
      deviceProfile: device,
      fayManifest,
      slicedProfile: thinProfile,
      remotePrimaryPointer: signedPointer,
      sliceSummary: {
        totalPrimaryThoughts: countThoughts(fullProfile.thought),
        bundledThoughts: 0,
        totalPrimarySkills: fullProfile.skill.length,
        bundledSkills: 0,
        bundledPersonas: 1,
        localEgoWeightsBundled: false,
        effectiveCapabilities,
        bufByteLength: bufBytes.length,
      },
      bufBytes,
      parsedBuf,
    };
  }

  // ==========================================================================
  // Mode 1 (plus/super Full Workstation) vs Mode 2 (lite/normal Edge Slice)
  // ==========================================================================
  const isFullWorkstation = device.tier === 'super' || device.tier === 'plus';
  const domainFilterSet = new Set([
    ...device.preferred_domains,
    ...(isFullWorkstation ? [] : activePersona.scenario_tags),
  ]);

  // Thought slicing
  const slicedThought = {
    content: [],
    data: [],
    knowledge_base: [],
    info_feed: [],
  };

  const maxThoughtBudgetBytes = isFullWorkstation
    ? Number.MAX_SAFE_INTEGER
    : device.tier === 'lite'
      ? Math.min(64 * 1024, device.free_storage_mb * 256)
      : Math.min(512 * 1024, device.free_storage_mb * 1024);

  let usedThoughtBytes = 0;
  for (const sub of THOUGHT_SUBTYPES) {
    for (const item of fullProfile.thought[sub]) {
      if (isFullWorkstation) {
        slicedThought[sub].push(structuredClone(item));
        usedThoughtBytes += item.byte_size;
        continue;
      }
      // Edge / Mobile domain & sensitivity & budget filter
      if (item.sensitivity === 'secret') continue;
      const matchesDomain =
        domainFilterSet.size === 0 ||
        domainFilterSet.has(item.domain) ||
        item.tags.some((t) => domainFilterSet.has(t));
      if (!matchesDomain) continue;
      if (usedThoughtBytes + item.byte_size > maxThoughtBudgetBytes) continue;
      slicedThought[sub].push(structuredClone(item));
      usedThoughtBytes += item.byte_size;
    }
  }

  // Skill slicing: match capabilities & domain
  const slicedSkills = fullProfile.skill.filter((sk) => {
    const capsSatisfied = sk.required_capabilities.every((c) => grantedSet.has(c));
    if (isFullWorkstation) {
      return capsSatisfied;
    }
    const domainMatched =
      domainFilterSet.size === 0 || sk.domains.some((d) => domainFilterSet.has(d));
    return capsSatisfied && domainMatched;
  });

  // Ego slicing: full multi-persona pod vs single compact distilled LoRA slice
  const bundledPersonas = isFullWorkstation ? adjustedPersonas : [activePersona];
  const egoSliceDescriptor = isFullWorkstation
    ? {
        schema_version: 'ifay-ego-slice/1.0',
        slice_mode: 'full_local_pod',
        active_persona_id: activePersona.persona_id,
        model_source: activePersona.model_source,
        personas_bundled: bundledPersonas.map((p) => p.persona_id),
        three_in_one_interfaces: ['fast_reflex', 'dynamic_context_injection', 'output_guard'],
        offline_capable: true,
        ego_school_enabled: device.tier === 'super',
      }
    : {
        schema_version: 'ifay-ego-slice/1.0',
        slice_mode: 'compact_distilled_slice',
        active_persona_id: activePersona.persona_id,
        compact_model_ref: activePersona.compact_slice_ref,
        scenario_tags: activePersona.scenario_tags,
        three_in_one_interfaces: ['fast_reflex', 'output_guard'],
        redlines: activePersona.redlines,
        offline_capable: true,
        ego_school_enabled: false,
      };

  const slicedProfile = {
    schema_version: fullProfile.schema_version,
    identity: structuredClone(fullProfile.identity),
    ego: {
      active_persona_id: activePersona.persona_id,
      personas: bundledPersonas,
      human_corrections: isFullWorkstation
        ? structuredClone(fullProfile.ego.human_corrections)
        : [],
    },
    thought: slicedThought,
    skill: structuredClone(slicedSkills),
    hardware: isFullWorkstation
      ? structuredClone(fullProfile.hardware)
      : {
          device: [{ id: device.device_id, label: device.platform_id, kind: device.tier, trusted: true }],
          storage: [],
          computing: [],
        },
    permissions: {
      inherent: [...fullProfile.permissions.inherent],
      persistent: isFullWorkstation ? [...fullProfile.permissions.persistent] : [],
      ephemeral: effectiveCapabilities,
      auth_methods: [...fullProfile.permissions.auth_methods],
    },
  };

  const slicedCheck = validateIfayProfile(slicedProfile);
  if (!slicedCheck.valid) {
    throw new Error(`Sliced iFay Profile failed validation: ${slicedCheck.errors.join(', ')}`);
  }

  const fayManifest = createFayManifest({
    name: `${fullProfile.identity.fay_id.slice(0, 14)}-${device.tier}`,
    version: '1.0.0',
    description: `${isFullWorkstation ? 'Full workstation' : 'Adaptive edge'} iFay Digital Soul slice for ${device.device_id}`,
    vendor: 'HumanPrime Self-Sovereign',
    fayId: primaryBody.fayId,
    controlMode: 'ego',
    modules: isFullWorkstation
      ? [
          { id: 'personal_data_heap', version: '^1.0.0' },
          { id: 'aligned_consciousness', version: '^1.0.0' },
          { id: 'registered_skill', version: '^1.0.0' },
          { id: 'invoke_skill', version: '^1.0.0' },
        ]
      : [
          { id: 'registered_skill', version: '^1.0.0' },
          { id: 'invoke_skill', version: '^1.0.0' },
        ],
    protocols: [
      { id: 'faying_protocol', version: '^1.0.0' },
      { id: 'cap_protocol', version: '^1.0.0' },
      ...(device.network_online ? [{ id: 'dtp_protocol', version: '^1.0.0' }] : []),
    ],
    ego: {
      modelSource: isFullWorkstation
        ? activePersona.model_source
        : activePersona.compact_slice_ref,
      scenarioTags: activePersona.scenario_tags,
      constraints: {
        skillBoundaries: {
          allowed: Array.from(new Set(slicedSkills.flatMap((s) => s.domains).concat(['general']))),
          restricted: ['unauthorized_financial_transfer', 'unverified_system_wipe'],
        },
      },
    },
    permissions: {
      inherent: slicedProfile.permissions.inherent,
      persistent: slicedProfile.permissions.persistent,
      authMethods: slicedProfile.permissions.auth_methods,
    },
  });

  const manifestValidation = validateFayManifest(fayManifest);
  if (!manifestValidation.valid) {
    throw new Error(`Sliced FayManifest invalid: ${manifestValidation.errors.join('; ')}`);
  }

  const taskIr = {
    schema_version: 'fayger-task-ir/1.0',
    embodiment_mode: isFullWorkstation ? 'full_embodiment' : 'compact_edge_slice',
    soul_fay_id: primaryBody.fayId,
    active_persona_id: activePersona.persona_id,
    target_device_id: device.device_id,
    steps: [],
  };

  const sections = [
    {
      id: 'code',
      kind: 'code',
      visibility: 'required',
      payload: Buffer.from(canonicalizeJcs(taskIr), 'utf8'),
    },
    {
      id: 'fay_manifest',
      kind: 'data',
      visibility: 'required',
      payload: Buffer.from(canonicalizeJcs(fayManifest), 'utf8'),
    },
    {
      id: 'soul_profile',
      kind: 'data',
      visibility: 'required',
      payload: Buffer.from(canonicalizeJcs(slicedProfile), 'utf8'),
    },
    {
      id: 'ego_slice',
      kind: 'data',
      visibility: 'required',
      payload: Buffer.from(canonicalizeJcs(egoSliceDescriptor), 'utf8'),
    },
    {
      id: 'thought_slice',
      kind: 'data',
      visibility: 'optional',
      payload: Buffer.from(canonicalizeJcs(slicedThought), 'utf8'),
    },
    {
      id: 'skill_slice',
      kind: 'data',
      visibility: 'optional',
      payload: Buffer.from(canonicalizeJcs(slicedSkills), 'utf8'),
    },
    {
      id: 'sync_anchor',
      kind: 'data',
      visibility: 'required',
      payload: Buffer.from(canonicalizeJcs(syncAnchor), 'utf8'),
    },
  ];

  if (device.tier === 'super' && fullProfile.ego.human_corrections.length > 0) {
    sections.push({
      id: 'ego_school_buffer',
      kind: 'data',
      visibility: 'optional',
      payload: Buffer.from(canonicalizeJcs(fullProfile.ego.human_corrections), 'utf8'),
    });
  }

  const mode = isFullWorkstation ? 'full_embodiment' : 'compact_edge_slice';
  const bufBytes = packBufBinary({
    schemaVersion: '1.0.0',
    runtimeInterfaceMin: '1.0.0',
    entry: 'main',
    capabilities: effectiveCapabilities,
    quotas,
    extensions: {
      fay_entity_kind: 'ifay',
      fay_id: primaryBody.fayId,
      embodiment_mode: mode,
      device_tier: device.tier,
      active_persona_id: activePersona.persona_id,
      state_root_sha256: primaryBody.stateRootSha256,
    },
    sections,
    ...(bufSigner ? { signer: bufSigner } : {}),
  });

  const parsedBuf = parseBufBinary(bufBytes, {
    ...(bufSigner ? { trustedPublicKeyHex: bufSigner.publicKeyHex } : {}),
  });

  return {
    mode,
    tier: device.tier,
    deviceProfile: device,
    fayManifest,
    slicedProfile,
    egoSliceDescriptor,
    syncAnchor,
    sliceSummary: {
      totalPrimaryThoughts: countThoughts(fullProfile.thought),
      bundledThoughts: countThoughts(slicedThought),
      totalPrimarySkills: fullProfile.skill.length,
      bundledSkills: slicedSkills.length,
      bundledPersonas: bundledPersonas.length,
      localEgoWeightsBundled: true,
      effectiveCapabilities,
      bufByteLength: bufBytes.length,
    },
    bufBytes,
    parsedBuf,
  };
}

function countThoughts(thoughtMap) {
  let total = 0;
  for (const sub of THOUGHT_SUBTYPES) {
    total += (thoughtMap[sub] ?? []).length;
  }
  return total;
}
