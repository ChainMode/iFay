import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  canonicalizeJcs,
  createFayManifest,
  deriveEntityKeypair,
  ed25519KeypairFromSeed,
  validateFayManifest,
  verifyEd25519,
} from '@ifay/sdk';
import {
  createInitialIfayProfile,
  ingestDtpContextFrame,
  normalizeSkillItem,
  normalizeThoughtItem,
  signPlatformRegistrationAttestation,
  validateIfayProfile,
} from './ifay-profile.mjs';

export const SOUL_LEDGER_EVENT_SCHEMA = 'ifay-soul-event/1.0';
export const SOUL_LEDGER_SIGNING_DOMAIN = 'ifay.soul.ledger.v1';
export const GENESIS_PARENT_HASH =
  '0000000000000000000000000000000000000000000000000000000000000000';

export const SOUL_EVENT_TYPES = Object.freeze([
  'soul_genesis',
  'thought_added',
  'dtp_context_ingested',
  'skill_registered',
  'hardware_updated',
  'permission_updated',
  'ego_persona_added',
  'ego_switched',
  'human_correction',
  'platform_registered',
  'platform_revoked',
]);

function sha256Hex(input) {
  return createHash('sha256').update(input).digest('hex');
}

function normalizeSeed(seedOrHex) {
  if (!seedOrHex) return randomBytes(32);
  if (typeof seedOrHex === 'string') {
    if (!/^[0-9a-fA-F]{64}$/.test(seedOrHex)) {
      throw new TypeError('Master seed hex must be 64 hex characters (32 bytes)');
    }
    return Buffer.from(seedOrHex, 'hex');
  }
  const buf = Buffer.from(seedOrHex);
  if (buf.length !== 32) {
    throw new RangeError('Master seed must be 32 bytes');
  }
  return buf;
}

export function createStarterThoughts(timestamp = '2026-11-20T00:00:00.000Z') {
  return [
    {
      subtype: 'knowledge_base',
      title: 'Distributed Architecture & Rust/Node Engineering Playbook',
      text: 'Prefer deterministic state machines, explicit capability intersections, zero hidden network calls, and canonical RFC 8785 / RFC 8949 wire formats.',
      domain: 'engineering',
      tags: ['architecture', 'rust', 'nodejs', 'fayger'],
      created_at: timestamp,
    },
    {
      subtype: 'content',
      title: 'Aerial Coastal Golden-Hour Framing Guide',
      text: 'Shoot at 35m altitude with 24mm equivalent focal length, ND16 filter, gimbal -18 deg pitch, avoiding residential zones.',
      domain: 'aerial_photography',
      tags: ['drone', 'camera', 'aerial_photography'],
      created_at: timestamp,
    },
    {
      subtype: 'data',
      title: 'Daily Deep-Work Schedule & Focus Preferences',
      text: 'Reserve 09:00-12:00 local time for uninterrupted architecture work; batch non-urgent notifications to 16:30.',
      domain: 'productivity',
      tags: ['calendar', 'focus', 'preferences'],
      created_at: timestamp,
    },
    {
      subtype: 'info_feed',
      title: 'Open Protocol & Systems Security Advisories Feed',
      text: 'Track weekly cryptographic protocol advisories, WebAssembly/sandbox isolation updates, and local MLX inference benchmarks.',
      domain: 'engineering',
      tags: ['security', 'protocols', 'mlx'],
      created_at: timestamp,
    },
  ];
}

export function createStarterSkills(timestamp = '2026-11-20T00:00:00.000Z') {
  return [
    {
      skill_type: 'agent',
      name: 'Workspace Codebase Architect',
      endpoint_or_package: '@ifay/skill-workspace-architect',
      domains: ['engineering', 'documentation'],
      required_capabilities: ['fs.read', 'fs.write'],
      preauthorized: true,
      registered_at: timestamp,
    },
    {
      skill_type: 'api',
      name: 'Gimbal & Aerial Framing Controller',
      endpoint_or_package: '@drone-drivers/aerial-framing-api',
      domains: ['aerial_photography', 'navigation'],
      required_capabilities: ['host.call'],
      preauthorized: true,
      registered_at: timestamp,
    },
    {
      skill_type: 'workflow',
      name: 'Weekly Engineering Digest Compiler',
      endpoint_or_package: '@ifay/workflow-weekly-digest',
      domains: ['productivity', 'engineering'],
      required_capabilities: ['fs.read', 'net.http'],
      preauthorized: true,
      registered_at: timestamp,
    },
  ];
}

export function createStarterHardware() {
  return {
    device: [
      { id: 'hw_mac_studio', label: 'Primary Workstation', kind: 'desktop', trusted: true },
      { id: 'hw_drone_mavic', label: 'Inspection & Photo Drone', kind: 'drone', trusted: true },
    ],
    storage: [
      { id: 'stg_local_nvme', label: 'Encrypted Local NVMe Primary Vault', capacity_gb: 2048 },
      { id: 'stg_nas_mirror', label: 'Home NAS Peer Primary Replica', capacity_gb: 4096 },
    ],
    computing: [
      { id: 'cmp_apple_mlx', label: 'Local Apple Silicon Unified Memory (Ego + Ego School)', vram_gb: 64 },
    ],
  };
}

function buildUnsignedEventCore(event) {
  const core = { ...event };
  delete core.event_hash;
  delete core.signature_hex;
  return core;
}

export function computeLedgerEventHash(event) {
  const core = buildUnsignedEventCore(event);
  return sha256Hex(Buffer.from(canonicalizeJcs(core), 'utf8'));
}

export function signLedgerEvent(unsignedEvent, signer) {
  const sortedParents = [...unsignedEvent.parents].sort();
  const normalizedUnsigned = {
    schema_version: SOUL_LEDGER_EVENT_SCHEMA,
    soul_fay_id: unsignedEvent.soul_fay_id,
    event_type: unsignedEvent.event_type,
    origin_replica_id: unsignedEvent.origin_replica_id,
    lamport_clock: unsignedEvent.lamport_clock,
    parents: sortedParents,
    timestamp: unsignedEvent.timestamp,
    payload: unsignedEvent.payload,
    signer_id: unsignedEvent.signer_id,
    signer_public_key_hex: signer.publicKeyHex,
  };
  const eventHash = computeLedgerEventHash(normalizedUnsigned);
  const sigPreimage = Buffer.from(`${SOUL_LEDGER_SIGNING_DOMAIN}\0${eventHash}`, 'utf8');
  const signatureHex = signer.signPayload(sigPreimage).toString('hex');
  return {
    ...normalizedUnsigned,
    event_hash: eventHash,
    signature_hex: signatureHex,
  };
}

export function verifySingleLedgerEvent(event, allowedPublicKeysSet = null) {
  if (!event || typeof event !== 'object') {
    return { valid: false, code: 'LEDGER_EVENT_NOT_OBJECT' };
  }
  if (event.schema_version !== SOUL_LEDGER_EVENT_SCHEMA) {
    return { valid: false, code: 'LEDGER_SCHEMA_INVALID' };
  }
  if (!SOUL_EVENT_TYPES.includes(event.event_type)) {
    return { valid: false, code: 'LEDGER_EVENT_TYPE_UNKNOWN' };
  }
  if (!Array.isArray(event.parents) || event.parents.length === 0) {
    return { valid: false, code: 'LEDGER_PARENTS_EMPTY' };
  }
  if (!Number.isInteger(event.lamport_clock) || event.lamport_clock < 0) {
    return { valid: false, code: 'LEDGER_CLOCK_INVALID' };
  }
  if (allowedPublicKeysSet && !allowedPublicKeysSet.has(event.signer_public_key_hex)) {
    return { valid: false, code: 'LEDGER_UNAUTHORIZED_SIGNER' };
  }
  const expectedHash = computeLedgerEventHash(event);
  if (expectedHash !== event.event_hash) {
    return { valid: false, code: 'LEDGER_HASH_MISMATCH', expectedHash, actualHash: event.event_hash };
  }
  const sigPreimage = Buffer.from(`${SOUL_LEDGER_SIGNING_DOMAIN}\0${event.event_hash}`, 'utf8');
  if (!verifyEd25519(event.signer_public_key_hex, sigPreimage, event.signature_hex)) {
    return { valid: false, code: 'LEDGER_SIGNATURE_INVALID' };
  }
  return { valid: true };
}

/**
 * Verifies a full causal DAG of signed ledger events and returns them in
 * strictly deterministic topological order:
 *   ready events ordered by (lamport_clock ASC, timestamp ASC, event_hash ASC).
 */
export function verifyAndSortLedgerEvents(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return { valid: false, code: 'LEDGER_EMPTY', message: 'Primary Body ledger has no events' };
  }

  const byHash = new Map();
  let genesis = null;

  for (const ev of events) {
    if (!ev || typeof ev.event_hash !== 'string') {
      return { valid: false, code: 'LEDGER_EVENT_MALFORMED' };
    }
    if (byHash.has(ev.event_hash)) {
      const existing = canonicalizeJcs(byHash.get(ev.event_hash));
      const candidate = canonicalizeJcs(ev);
      if (existing !== candidate) {
        return { valid: false, code: 'LEDGER_EQUIVOCATION_DETECTED', eventHash: ev.event_hash };
      }
      continue;
    }
    byHash.set(ev.event_hash, ev);
    if (ev.event_type === 'soul_genesis') {
      if (genesis && genesis.event_hash !== ev.event_hash) {
        return { valid: false, code: 'LEDGER_MULTIPLE_GENESIS' };
      }
      genesis = ev;
    }
  }

  if (!genesis) {
    return { valid: false, code: 'LEDGER_GENESIS_MISSING' };
  }
  if (genesis.parents.length !== 1 || genesis.parents[0] !== GENESIS_PARENT_HASH) {
    return { valid: false, code: 'LEDGER_GENESIS_PARENT_INVALID' };
  }

  const genesisProfile = genesis.payload?.initial_profile;
  if (!genesisProfile?.identity?.fay_id) {
    return { valid: false, code: 'LEDGER_GENESIS_PAYLOAD_INVALID' };
  }
  const soulFayId = genesisProfile.identity.fay_id;
  const allowedSigners = new Set(
    [
      genesisProfile.identity.entity_public_key_hex,
      genesisProfile.identity.human_prime_public_key_hex,
      ...(genesis.payload?.authorized_embodiment_pubkeys ?? []),
    ].filter(Boolean),
  );

  for (const ev of byHash.values()) {
    if (ev.soul_fay_id !== soulFayId) {
      return { valid: false, code: 'LEDGER_SOUL_ID_MISMATCH', eventHash: ev.event_hash };
    }
    const singleCheck = verifySingleLedgerEvent(ev, allowedSigners);
    if (!singleCheck.valid) {
      return { ...singleCheck, eventHash: ev.event_hash };
    }
    if (ev.event_type !== 'soul_genesis') {
      for (const pHash of ev.parents) {
        const parentEv = byHash.get(pHash);
        if (!parentEv) {
          return {
            valid: false,
            code: 'LEDGER_PARENT_MISSING',
            eventHash: ev.event_hash,
            missingParentHash: pHash,
          };
        }
        if (ev.lamport_clock <= parentEv.lamport_clock) {
          return {
            valid: false,
            code: 'LEDGER_CAUSAL_CLOCK_VIOLATION',
            eventHash: ev.event_hash,
          };
        }
      }
    }
  }

  // Kahn's topological sort with deterministic min-selection:
  // (lamport_clock ASC, timestamp ASC, event_hash ASC)
  const inDegree = new Map();
  const children = new Map();
  for (const h of byHash.keys()) {
    inDegree.set(h, 0);
    children.set(h, []);
  }
  for (const ev of byHash.values()) {
    if (ev.event_type === 'soul_genesis') continue;
    let deg = 0;
    for (const pHash of ev.parents) {
      deg += 1;
      children.get(pHash).push(ev.event_hash);
    }
    inDegree.set(ev.event_hash, deg);
  }

  const compareEvents = (a, b) => {
    if (a.lamport_clock !== b.lamport_clock) return a.lamport_clock - b.lamport_clock;
    if (a.timestamp !== b.timestamp) return a.timestamp < b.timestamp ? -1 : 1;
    return a.event_hash < b.event_hash ? -1 : a.event_hash > b.event_hash ? 1 : 0;
  };

  const ready = [];
  for (const [h, deg] of inDegree.entries()) {
    if (deg === 0) ready.push(byHash.get(h));
  }
  ready.sort(compareEvents);

  const ordered = [];
  const referencedAsParent = new Set();
  for (const ev of byHash.values()) {
    for (const p of ev.parents) referencedAsParent.add(p);
  }

  while (ready.length > 0) {
    const current = ready.shift();
    ordered.push(current);
    for (const childHash of children.get(current.event_hash)) {
      const nextDeg = inDegree.get(childHash) - 1;
      inDegree.set(childHash, nextDeg);
      if (nextDeg === 0) {
        ready.push(byHash.get(childHash));
        ready.sort(compareEvents);
      }
    }
  }

  if (ordered.length !== byHash.size) {
    return { valid: false, code: 'LEDGER_CYCLE_DETECTED' };
  }

  const headHashes = Array.from(byHash.keys())
    .filter((h) => !referencedAsParent.has(h))
    .sort();

  return {
    valid: true,
    genesisHash: genesis.event_hash,
    soulFayId,
    orderedEvents: ordered,
    headHashes,
    allowedSigners,
  };
}

export function materializeSoulState(orderedEvents) {
  const genesis = orderedEvents[0];
  const profile = structuredClone(genesis.payload.initial_profile);

  const seenThoughtIds = new Set();
  for (const sub of Object.keys(profile.thought)) {
    for (const item of profile.thought[sub]) {
      seenThoughtIds.add(item.thought_id);
    }
  }
  const seenSkillIds = new Set(profile.skill.map((s) => s.skill_id));
  const seenCorrectionIds = new Set(
    (profile.ego.human_corrections ?? []).map((c) => c.correction_id),
  );

  for (let i = 1; i < orderedEvents.length; i += 1) {
    const ev = orderedEvents[i];
    const p = ev.payload;

    switch (ev.event_type) {
      case 'thought_added':
      case 'dtp_context_ingested': {
        const item = normalizeThoughtItem(p.thought, ev.timestamp);
        if (!seenThoughtIds.has(item.thought_id)) {
          seenThoughtIds.add(item.thought_id);
          profile.thought[item.subtype].push(item);
        }
        break;
      }
      case 'skill_registered': {
        const sk = normalizeSkillItem(p.skill, ev.timestamp);
        if (!seenSkillIds.has(sk.skill_id)) {
          seenSkillIds.add(sk.skill_id);
          profile.skill.push(sk);
        }
        break;
      }
      case 'hardware_updated': {
        const { subtype, entry } = p;
        if (Array.isArray(profile.hardware[subtype])) {
          const idx = profile.hardware[subtype].findIndex((x) => x.id === entry.id);
          if (idx >= 0) {
            profile.hardware[subtype][idx] = structuredClone(entry);
          } else {
            profile.hardware[subtype].push(structuredClone(entry));
          }
        }
        break;
      }
      case 'permission_updated': {
        const { lifecycle, action = 'grant', permission } = p;
        if (Array.isArray(profile.permissions[lifecycle])) {
          if (action === 'revoke') {
            profile.permissions[lifecycle] = profile.permissions[lifecycle].filter(
              (x) => x !== permission,
            );
          } else if (!profile.permissions[lifecycle].includes(permission)) {
            profile.permissions[lifecycle].push(permission);
          }
        }
        break;
      }
      case 'ego_persona_added': {
        const persona = structuredClone(p.persona);
        const existingIdx = profile.ego.personas.findIndex(
          (x) => x.persona_id === persona.persona_id,
        );
        persona.active = false;
        if (existingIdx >= 0) {
          persona.active = profile.ego.personas[existingIdx].active;
          profile.ego.personas[existingIdx] = persona;
        } else {
          profile.ego.personas.push(persona);
        }
        break;
      }
      case 'ego_switched': {
        const targetId = p.active_persona_id;
        const exists = profile.ego.personas.some((x) => x.persona_id === targetId);
        if (!exists) {
          throw new Error(`Cannot switch Ego to unknown persona '${targetId}'`);
        }
        profile.ego.active_persona_id = targetId;
        for (const persona of profile.ego.personas) {
          persona.active = persona.persona_id === targetId;
        }
        break;
      }
      case 'human_correction': {
        const corr = {
          correction_id: p.correction_id ?? `cor_${ev.event_hash.slice(0, 16)}`,
          persona_id: p.persona_id ?? profile.ego.active_persona_id,
          prompt_context: p.prompt_context,
          rejected_output: p.rejected_output,
          preferred_output: p.preferred_output,
          extracted_rule: p.extracted_rule ?? null,
          source_device_id: p.source_device_id ?? ev.origin_replica_id,
          recorded_at: ev.timestamp,
          event_hash: ev.event_hash,
        };
        if (!seenCorrectionIds.has(corr.correction_id)) {
          seenCorrectionIds.add(corr.correction_id);
          profile.ego.human_corrections.push(corr);
          if (corr.extracted_rule) {
            const targetPersona = profile.ego.personas.find(
              (x) => x.persona_id === corr.persona_id,
            );
            if (targetPersona && !targetPersona.redlines.includes(corr.extracted_rule)) {
              targetPersona.redlines.push(corr.extracted_rule);
            }
          }
        }
        break;
      }
      case 'platform_registered': {
        const att = structuredClone(p.attestation);
        const existingIdx = profile.identity.platform_registrations.findIndex(
          (x) => x.platform_id === att.platform_id,
        );
        if (existingIdx >= 0) {
          profile.identity.platform_registrations[existingIdx] = att;
        } else {
          profile.identity.platform_registrations.push(att);
        }
        profile.identity.visibility_mode = profile.identity.platform_registrations.some(
          (x) => !x.revoked_at && x.discoverable,
        )
          ? 'registered_opt_in'
          : 'stealth';
        break;
      }
      case 'platform_revoked': {
        for (const reg of profile.identity.platform_registrations) {
          if (reg.platform_id === p.platform_id) {
            reg.revoked_at = ev.timestamp;
          }
        }
        profile.identity.visibility_mode = profile.identity.platform_registrations.some(
          (x) => !x.revoked_at && x.discoverable,
        )
          ? 'registered_opt_in'
          : 'stealth';
        break;
      }
      default:
        break;
    }
  }

  const validation = validateIfayProfile(profile);
  if (!validation.valid) {
    throw new Error(`Materialized iFay Profile failed validation: ${validation.errors.join(', ')}`);
  }

  const eventChainDigest = sha256Hex(
    Buffer.from(orderedEvents.map((e) => e.event_hash).join(':'), 'utf8'),
  );
  const profileDigest = sha256Hex(Buffer.from(canonicalizeJcs(profile), 'utf8'));
  const stateRootSha256 = sha256Hex(
    Buffer.from(`${profileDigest}:${eventChainDigest}`, 'utf8'),
  );

  return {
    profile,
    profileDigest,
    eventChainDigest,
    stateRootSha256,
  };
}

export function buildSoulFayManifest(profile) {
  const activePersona = profile.ego.personas.find(
    (p) => p.persona_id === profile.ego.active_persona_id,
  );
  const manifest = createFayManifest({
    name: profile.identity.display_name
      .toLowerCase()
      .replace(/[^a-z0-9-]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'personal-ifay-soul',
    version: '1.0.0',
    description: profile.identity.bio,
    vendor: 'HumanPrime Self-Sovereign',
    fayId: profile.identity.fay_id,
    controlMode: 'ego',
    modules: [
      { id: 'personal_data_heap', version: '^1.0.0' },
      { id: 'aligned_consciousness', version: '^1.0.0' },
      { id: 'registered_skill', version: '^1.0.0' },
      { id: 'invoke_skill', version: '^1.0.0' },
    ],
    protocols: [
      { id: 'faying_protocol', version: '^1.0.0' },
      { id: 'cap_protocol', version: '^1.0.0' },
      { id: 'dtp_protocol', version: '^1.0.0' },
      { id: 'icp_protocol', version: '^1.0.0' },
    ],
    ego: {
      modelSource: activePersona?.model_source ?? '@ego-models/personal-core-v1',
      scenarioTags: activePersona?.scenario_tags ?? ['general'],
      constraints: {
        skillBoundaries: {
          allowed: Array.from(new Set(profile.skill.flatMap((s) => s.domains))),
          restricted: ['unauthorized_financial_transfer', 'unverified_system_wipe'],
        },
      },
    },
    permissions: {
      inherent: profile.permissions.inherent,
      persistent: profile.permissions.persistent,
      authMethods: profile.permissions.auth_methods,
    },
  });
  const check = validateFayManifest(manifest);
  if (!check.valid) {
    throw new Error(`Generated Soul FayManifest invalid: ${check.errors.join('; ')}`);
  }
  return manifest;
}

export class PrimaryBodyStore {
  constructor({
    replicaId,
    dirPath = null,
    events = [],
    signer = null,
    signerId = null,
    humanPrimeSigner = null,
    entitySeed32 = null,
  }) {
    this.replicaId = replicaId;
    this.dirPath = dirPath ? resolve(dirPath) : null;
    this.events = events;
    this.signer = signer;
    this.signerId = signerId;
    this.humanPrimeSigner = humanPrimeSigner;
    this.entitySeed32 = entitySeed32;
    this._rebuildMaterializedState();
  }

  static init(options = {}) {
    const masterSeed = normalizeSeed(options.masterSeed);
    const createdAt = options.createdAt ?? '2026-11-20T00:00:00.000Z';
    const replicaId = options.replicaId ?? 'replica:primary-01';

    const hidRes = deriveEntityKeypair(masterSeed, 'hid', options.humanSlot ?? 0);
    if (!hidRes.ok) throw new Error(hidRes.error);
    const ifayRes = deriveEntityKeypair(masterSeed, 'ifay', options.ifaySlot ?? 0);
    if (!ifayRes.ok) throw new Error(ifayRes.error);

    const humanPrime = hidRes.value;
    const ifayEntity = ifayRes.value;

    // Derive deterministic 32B entity signing seed for BuF seal_and_sign compatibility
    const bufSigningSeed32 = createHash('sha256')
      .update(Buffer.concat([masterSeed, Buffer.from(`buf-seal:${ifayEntity.entityId}`, 'utf8')]))
      .digest();
    const bufSignerKp = ed25519KeypairFromSeed(bufSigningSeed32);

    const includeStarters = options.includeStarters !== false;
    const initialProfile = createInitialIfayProfile({
      fayId: ifayEntity.entityId,
      humanPrimeId: humanPrime.entityId,
      entityPublicKeyHex: ifayEntity.publicKeyHex,
      humanPrimePublicKeyHex: humanPrime.publicKeyHex,
      displayName: options.displayName ?? 'Personal iFay Soul',
      bio: options.bio ?? 'Portable Digital Soul bound to Human Prime',
      createdAt,
      personas: options.personas,
      activePersonaId: options.activePersonaId ?? 'professional',
      initialThoughts: options.initialThoughts ?? (includeStarters ? createStarterThoughts(createdAt) : []),
      initialSkills: options.initialSkills ?? (includeStarters ? createStarterSkills(createdAt) : []),
      initialHardware: options.initialHardware ?? (includeStarters ? createStarterHardware() : undefined),
      initialPermissions: options.initialPermissions,
    });

    const genesisEvent = signLedgerEvent(
      {
        soul_fay_id: ifayEntity.entityId,
        event_type: 'soul_genesis',
        origin_replica_id: replicaId,
        lamport_clock: 0,
        parents: [GENESIS_PARENT_HASH],
        timestamp: createdAt,
        payload: {
          initial_profile: initialProfile,
          buf_signing_public_key_hex: bufSignerKp.publicKeyHex,
          authorized_embodiment_pubkeys: options.authorizedEmbodimentPubkeys ?? [],
        },
        signer_id: humanPrime.entityId,
      },
      humanPrime,
    );

    const store = new PrimaryBodyStore({
      replicaId,
      dirPath: options.dirPath ?? null,
      events: [genesisEvent],
      signer: ifayEntity,
      signerId: ifayEntity.entityId,
      humanPrimeSigner: humanPrime,
      entitySeed32: bufSigningSeed32,
    });

    if (store.dirPath) {
      store._saveKeystore(masterSeed, bufSigningSeed32);
      store.save();
    }
    return store;
  }

  static createPeerReplica(sourceStore, { replicaId = 'replica:peer-02', dirPath = null } = {}) {
    const clonedEvents = structuredClone(sourceStore.events);
    const peer = new PrimaryBodyStore({
      replicaId,
      dirPath,
      events: clonedEvents,
      signer: sourceStore.signer,
      signerId: sourceStore.signerId,
      humanPrimeSigner: sourceStore.humanPrimeSigner,
      entitySeed32: sourceStore.entitySeed32 ? Buffer.from(sourceStore.entitySeed32) : null,
    });
    if (peer.dirPath) {
      if (sourceStore.dirPath && existsSync(join(sourceStore.dirPath, '.keystore.json'))) {
        const ks = JSON.parse(readFileSync(join(sourceStore.dirPath, '.keystore.json'), 'utf8'));
        peer._saveKeystore(
          Buffer.from(ks.master_seed_hex, 'hex'),
          Buffer.from(ks.buf_signing_seed_hex, 'hex'),
        );
      }
      peer.save();
    }
    return peer;
  }

  static load(dirPath) {
    const abs = resolve(dirPath);
    const ledgerPath = join(abs, 'ledger.json');
    if (!existsSync(ledgerPath)) {
      throw new Error(`Primary Body ledger.json not found in ${abs}`);
    }
    const ledgerDoc = JSON.parse(readFileSync(ledgerPath, 'utf8'));
    let ifaySigner = null;
    let humanSigner = null;
    let bufSeed32 = null;

    const ksPath = join(abs, '.keystore.json');
    if (existsSync(ksPath)) {
      const ks = JSON.parse(readFileSync(ksPath, 'utf8'));
      const masterSeed = Buffer.from(ks.master_seed_hex, 'hex');
      const hidRes = deriveEntityKeypair(masterSeed, 'hid', ks.human_slot ?? 0);
      const ifayRes = deriveEntityKeypair(masterSeed, 'ifay', ks.ifay_slot ?? 0);
      if (hidRes.ok) humanSigner = hidRes.value;
      if (ifayRes.ok) ifaySigner = ifayRes.value;
      if (ks.buf_signing_seed_hex) {
        bufSeed32 = Buffer.from(ks.buf_signing_seed_hex, 'hex');
      }
    }

    return new PrimaryBodyStore({
      replicaId: ledgerDoc.replica_id ?? 'replica:loaded',
      dirPath: abs,
      events: ledgerDoc.events,
      signer: ifaySigner,
      signerId: ifaySigner?.entityId ?? null,
      humanPrimeSigner: humanSigner,
      entitySeed32: bufSeed32,
    });
  }

  _saveKeystore(masterSeed, bufSigningSeed32) {
    if (!this.dirPath) return;
    mkdirSync(this.dirPath, { recursive: true });
    const ksPath = join(this.dirPath, '.keystore.json');
    writeFileSync(
      ksPath,
      `${JSON.stringify(
        {
          schema: 'ifay-soul-local-keystore/1.0',
          master_seed_hex: Buffer.from(masterSeed).toString('hex'),
          buf_signing_seed_hex: Buffer.from(bufSigningSeed32).toString('hex'),
          human_slot: 0,
          ifay_slot: 0,
        },
        null,
        2,
      )}\n`,
      { encoding: 'utf8', mode: 0o600 },
    );
    try {
      chmodSync(ksPath, 0o600);
    } catch {
      // Ignore chmod error on filesystems without POSIX perms
    }
  }

  _rebuildMaterializedState() {
    const check = verifyAndSortLedgerEvents(this.events);
    if (!check.valid) {
      throw new Error(`PrimaryBody ledger verification failed [${check.code}]: ${check.eventHash ?? ''}`);
    }
    this.events = check.orderedEvents;
    this.genesisHash = check.genesisHash;
    this.fayId = check.soulFayId;
    this.headHashes = check.headHashes;
    const mat = materializeSoulState(this.events);
    this.profile = mat.profile;
    this.profileDigest = mat.profileDigest;
    this.eventChainDigest = mat.eventChainDigest;
    this.stateRootSha256 = mat.stateRootSha256;
    this.fayManifest = buildSoulFayManifest(this.profile);
  }

  verifyLedger() {
    return verifyAndSortLedgerEvents(this.events);
  }

  nextLamportClock() {
    let maxClock = 0;
    for (const ev of this.events) {
      if (ev.lamport_clock > maxClock) maxClock = ev.lamport_clock;
    }
    return maxClock + 1;
  }

  commitEvent({
    eventType,
    payload,
    originReplicaId,
    timestamp,
    useHumanPrimeSigner = false,
    customSigner = null,
    customSignerId = null,
  }) {
    const activeSigner =
      customSigner ?? (useHumanPrimeSigner ? this.humanPrimeSigner : this.signer);
    const activeSignerId =
      customSignerId ??
      (useHumanPrimeSigner
        ? this.profile.identity.human_prime_id
        : this.signerId ?? this.profile.identity.fay_id);

    if (!activeSigner) {
      throw new Error('PrimaryBodyStore has no active Ed25519 signer loaded');
    }

    const signedEvent = signLedgerEvent(
      {
        soul_fay_id: this.fayId,
        event_type: eventType,
        origin_replica_id: originReplicaId ?? this.replicaId,
        lamport_clock: this.nextLamportClock(),
        parents: [...this.headHashes],
        timestamp:
          timestamp ??
          new Date(Date.UTC(2026, 10, 20, 0, 0, this.nextLamportClock())).toISOString(),
        payload,
        signer_id: activeSignerId,
      },
      activeSigner,
    );

    this.events.push(signedEvent);
    this._rebuildMaterializedState();
    if (this.dirPath) this.save();
    return signedEvent;
  }

  addThought(thoughtInput, options = {}) {
    const normalized = normalizeThoughtItem(thoughtInput, options.timestamp);
    return this.commitEvent({
      eventType: 'thought_added',
      payload: { thought: normalized },
      originReplicaId: options.originDeviceId ?? this.replicaId,
      timestamp: options.timestamp,
    });
  }

  ingestDtpFrame(wireFrameBytes, sessionKey32, options = {}) {
    const res = ingestDtpContextFrame(wireFrameBytes, sessionKey32, {
      createdAt: options.timestamp,
    });
    if (!res.ok) {
      throw new Error(`DTP context ingestion failed: ${res.errorCode}`);
    }
    const event = this.commitEvent({
      eventType: 'dtp_context_ingested',
      payload: {
        dtp_agreement_id: res.header.agreementId,
        dtp_fragment_id: res.header.fragmentId,
        dtp_sequence: res.header.sequenceNumber,
        thought: res.thoughtItem,
      },
      originReplicaId:
        options.originDeviceId ?? `dtp:${res.header.encryptionMetadata?.keyId ?? this.replicaId}`,
      timestamp: options.timestamp,
    });
    return { event, thoughtItem: res.thoughtItem };
  }

  registerSkill(skillInput, options = {}) {
    const normalized = normalizeSkillItem(skillInput, options.timestamp);
    return this.commitEvent({
      eventType: 'skill_registered',
      payload: { skill: normalized },
      originReplicaId: options.originDeviceId ?? this.replicaId,
      timestamp: options.timestamp,
    });
  }

  addPersona(personaInput, options = {}) {
    return this.commitEvent({
      eventType: 'ego_persona_added',
      payload: {
        persona: {
          persona_id: personaInput.persona_id,
          label: personaInput.label ?? personaInput.persona_id,
          active: false,
          model_source: personaInput.model_source ?? '@ego-models/personal-core-v1',
          compact_slice_ref:
            personaInput.compact_slice_ref ?? `@ego-models/${personaInput.persona_id}-lite-v1`,
          edition_version: personaInput.edition_version ?? '1.0.0',
          scenario_tags: personaInput.scenario_tags ?? ['general'],
          style_traits: personaInput.style_traits ?? ['aligned'],
          redlines: personaInput.redlines ?? [],
          bound_fay_id: this.fayId,
        },
      },
      originReplicaId: options.originDeviceId ?? this.replicaId,
      timestamp: options.timestamp,
      useHumanPrimeSigner: true,
    });
  }

  switchActiveEgo(personaId, options = {}) {
    return this.commitEvent({
      eventType: 'ego_switched',
      payload: {
        active_persona_id: personaId,
        reason: options.reason ?? 'manual_or_context_trigger',
      },
      originReplicaId: options.originDeviceId ?? this.replicaId,
      timestamp: options.timestamp,
    });
  }

  recordHumanCorrection(
    {
      promptContext,
      rejectedOutput,
      preferredOutput,
      extractedRule = null,
      personaId,
      sourceDeviceId,
    },
    options = {},
  ) {
    return this.commitEvent({
      eventType: 'human_correction',
      payload: {
        persona_id: personaId ?? this.profile.ego.active_persona_id,
        prompt_context: promptContext,
        rejected_output: rejectedOutput,
        preferred_output: preferredOutput,
        extracted_rule: extractedRule,
        source_device_id: sourceDeviceId ?? this.replicaId,
      },
      originReplicaId: sourceDeviceId ?? this.replicaId,
      timestamp: options.timestamp,
      useHumanPrimeSigner: Boolean(this.humanPrimeSigner),
    });
  }

  registerPlatform(
    {
      platformId,
      category = 'expert',
      handleOrRef,
      discoverable = true,
      scopes = ['profile.identity', 'skill.public'],
    },
    options = {},
  ) {
    const signer = this.humanPrimeSigner ?? this.signer;
    const timestamp =
      options.timestamp ??
      new Date(Date.UTC(2026, 10, 20, 0, 0, this.nextLamportClock())).toISOString();
    const attestation = signPlatformRegistrationAttestation(
      {
        fayId: this.fayId,
        platformId,
        category,
        handleOrRef,
        discoverable,
        scopes,
        registeredAt: timestamp,
      },
      signer,
    );
    return this.commitEvent({
      eventType: 'platform_registered',
      payload: { attestation },
      originReplicaId: options.originDeviceId ?? this.replicaId,
      timestamp,
      useHumanPrimeSigner: Boolean(this.humanPrimeSigner),
    });
  }

  revokePlatform(platformId, options = {}) {
    return this.commitEvent({
      eventType: 'platform_revoked',
      payload: { platform_id: platformId },
      originReplicaId: options.originDeviceId ?? this.replicaId,
      timestamp: options.timestamp,
      useHumanPrimeSigner: Boolean(this.humanPrimeSigner),
    });
  }

  commitEmbodimentDelta(delta, options = {}) {
    switch (delta.type) {
      case 'thought_added':
        return this.addThought(delta.thought, {
          originDeviceId: delta.deviceId,
          timestamp: delta.timestamp ?? options.timestamp,
        });
      case 'skill_registered':
        return this.registerSkill(delta.skill, {
          originDeviceId: delta.deviceId,
          timestamp: delta.timestamp ?? options.timestamp,
        });
      case 'human_correction':
        return this.recordHumanCorrection(
          { ...delta, sourceDeviceId: delta.deviceId },
          { timestamp: delta.timestamp ?? options.timestamp },
        );
      case 'ego_switched':
        return this.switchActiveEgo(delta.personaId, {
          originDeviceId: delta.deviceId,
          reason: delta.reason,
          timestamp: delta.timestamp ?? options.timestamp,
        });
      case 'platform_registered':
        return this.registerPlatform(delta, {
          originDeviceId: delta.deviceId,
          timestamp: delta.timestamp ?? options.timestamp,
        });
      default:
        throw new Error(`Unsupported embodiment delta type '${String(delta.type)}'`);
    }
  }

  getBufSigner() {
    if (!this.entitySeed32) return null;
    const kp = ed25519KeypairFromSeed(this.entitySeed32);
    return {
      seed32: this.entitySeed32,
      publicKeyRef: `${this.fayId}#buf-seal-v1`,
      publicKeyHex: kp.publicKeyHex,
    };
  }

  save() {
    if (!this.dirPath) return;
    mkdirSync(this.dirPath, { recursive: true });
    const ledgerDoc = {
      schema_version: 'ifay-primary-body-ledger/1.0',
      replica_id: this.replicaId,
      soul_fay_id: this.fayId,
      genesis_hash: this.genesisHash,
      head_hashes: this.headHashes,
      state_root_sha256: this.stateRootSha256,
      event_count: this.events.length,
      events: this.events,
    };
    writeFileSync(join(this.dirPath, 'ledger.json'), `${JSON.stringify(ledgerDoc, null, 2)}\n`, 'utf8');
    writeFileSync(
      join(this.dirPath, 'profile.json'),
      `${JSON.stringify(this.profile, null, 2)}\n`,
      'utf8',
    );
    writeFileSync(
      join(this.dirPath, 'faymanifest.json'),
      `${JSON.stringify(this.fayManifest, null, 2)}\n`,
      'utf8',
    );
  }
}

/**
 * Deterministically reconciles two peer Primary Body replicas (append-only causal DAG merge).
 * Verifies every Ed25519 signature, SHA-256 event hash, and shared genesis before mutating either side.
 */
export function syncPrimaryReplicas(replicaA, replicaB) {
  const checkA = replicaA.verifyLedger();
  if (!checkA.valid) {
    return { ok: false, side: 'replicaA', errorCode: checkA.code, detail: checkA };
  }
  const checkB = replicaB.verifyLedger();
  if (!checkB.valid) {
    return { ok: false, side: 'replicaB', errorCode: checkB.code, detail: checkB };
  }

  if (checkA.genesisHash !== checkB.genesisHash || checkA.soulFayId !== checkB.soulFayId) {
    return {
      ok: false,
      errorCode: 'LEDGER_GENESIS_MISMATCH',
      genesisA: checkA.genesisHash,
      genesisB: checkB.genesisHash,
    };
  }

  const hashesA = new Set(replicaA.events.map((e) => e.event_hash));
  const hashesB = new Set(replicaB.events.map((e) => e.event_hash));

  const mergedCandidates = [...replicaA.events];
  let pulledIntoA = 0;
  let pulledIntoB = 0;

  for (const ev of replicaB.events) {
    if (!hashesA.has(ev.event_hash)) {
      pulledIntoA += 1;
      mergedCandidates.push(structuredClone(ev));
    }
  }
  for (const ev of replicaA.events) {
    if (!hashesB.has(ev.event_hash)) {
      pulledIntoB += 1;
    }
  }

  const mergedVerification = verifyAndSortLedgerEvents(mergedCandidates);
  if (!mergedVerification.valid) {
    return {
      ok: false,
      errorCode: mergedVerification.code,
      detail: mergedVerification,
    };
  }

  replicaA.events = structuredClone(mergedVerification.orderedEvents);
  replicaB.events = structuredClone(mergedVerification.orderedEvents);
  replicaA._rebuildMaterializedState();
  replicaB._rebuildMaterializedState();

  if (replicaA.dirPath) replicaA.save();
  if (replicaB.dirPath) replicaB.save();

  return {
    ok: true,
    soulFayId: replicaA.fayId,
    genesisHash: replicaA.genesisHash,
    totalEvents: replicaA.events.length,
    pulledIntoA,
    pulledIntoB,
    headHashes: replicaA.headHashes,
    stateRootSha256: replicaA.stateRootSha256,
    consistent: replicaA.stateRootSha256 === replicaB.stateRootSha256,
  };
}
