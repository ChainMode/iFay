import { createHash } from 'node:crypto';
import {
  canonicalizeJcs,
  decodeDtpFrame,
  encodeDtpFrame,
  isValidFayId,
  verifyEd25519,
} from '@ifay/sdk';

export const IFAY_PROFILE_SCHEMA_VERSION = 'ifay-profile/1.0';
export const PLATFORM_ATTESTATION_DOMAIN = 'ifay.soul.platform-registration.v1';

export const THOUGHT_SUBTYPES = Object.freeze([
  'content',
  'data',
  'knowledge_base',
  'info_feed',
]);

export const SKILL_TYPES = Object.freeze([
  'api',
  'workflow',
  'bot',
  'agent',
  'app',
  'microservice',
]);

export const HARDWARE_SUBTYPES = Object.freeze([
  'device',
  'storage',
  'computing',
]);

export const PERMISSION_LIFECYCLES = Object.freeze([
  'inherent',
  'persistent',
  'ephemeral',
]);

export const PLATFORM_CATEGORIES = Object.freeze([
  'real_name',
  'expert',
  'commerce',
  'service',
  'social',
]);

function sha256Hex(textOrBytes) {
  return createHash('sha256').update(textOrBytes).digest('hex');
}

export function createStarterPersonas(fayId) {
  return [
    {
      persona_id: 'professional',
      label: 'Professional Work Mode',
      active: true,
      model_source: '@ego-models/personal-core-v1',
      compact_slice_ref: '@ego-models/personal-pro-lite-lora-v1',
      edition_version: '1.0.0',
      scenario_tags: ['engineering', 'architecture', 'email', 'productivity', 'documentation'],
      style_traits: ['concise', 'rigorous', 'evidence-driven'],
      redlines: [
        'Never leak private credentials or personal medical/financial records',
        'Never execute irreversible destructive commands without explicit Human Prime confirmation',
      ],
      bound_fay_id: fayId,
    },
    {
      persona_id: 'casual',
      label: 'Casual Life & Creative Mode',
      active: false,
      model_source: '@ego-models/personal-core-v1',
      compact_slice_ref: '@ego-models/personal-casual-lite-lora-v1',
      edition_version: '1.0.0',
      scenario_tags: ['dining', 'travel', 'photography', 'aerial_photography', 'music'],
      style_traits: ['warm', 'relaxed', 'taste-aware'],
      redlines: [
        'Never share real-time home location with unverified external services',
        'Never commit financial purchases above pre-authorized limits',
      ],
      bound_fay_id: fayId,
    },
  ];
}

export function createInitialIfayProfile({
  fayId,
  humanPrimeId,
  entityPublicKeyHex,
  humanPrimePublicKeyHex,
  displayName = 'Personal iFay Soul',
  bio = 'Portable Digital Soul bound to Human Prime',
  createdAt = '2026-11-20T00:00:00.000Z',
  personas,
  activePersonaId = 'professional',
  initialThoughts = [],
  initialSkills = [],
  initialHardware,
  initialPermissions,
}) {
  if (!isValidFayId(fayId, 'IFAY_ID')) {
    throw new Error(`Invalid iFay ID '${String(fayId)}'`);
  }
  if (!isValidFayId(humanPrimeId, 'HUMAN_ID')) {
    throw new Error(`Invalid Human Prime ID '${String(humanPrimeId)}'`);
  }

  const basePersonas = (personas && personas.length > 0 ? personas : createStarterPersonas(fayId)).map(
    (p) => ({
      ...p,
      active: p.persona_id === activePersonaId,
    }),
  );

  const activeCount = basePersonas.filter((p) => p.active === true).length;
  if (activeCount !== 1) {
    throw new Error(
      `SINGLE_ACTIVE_EGO_INVARIANT: expected exactly 1 active persona ('${activePersonaId}'), found ${activeCount}`,
    );
  }

  const thought = {
    content: [],
    data: [],
    knowledge_base: [],
    info_feed: [],
  };

  for (const item of initialThoughts) {
    const normalized = normalizeThoughtItem(item, createdAt);
    thought[normalized.subtype].push(normalized);
  }

  const skills = initialSkills.map((s) => normalizeSkillItem(s, createdAt));

  const hardware = {
    device: [...(initialHardware?.device ?? [])],
    storage: [...(initialHardware?.storage ?? [])],
    computing: [...(initialHardware?.computing ?? [])],
  };

  const permissions = {
    inherent: [...(initialPermissions?.inherent ?? ['calendar.read', 'preferences.read'])],
    persistent: [...(initialPermissions?.persistent ?? ['workspace.notes.read_write'])],
    ephemeral: [...(initialPermissions?.ephemeral ?? [])],
    auth_methods: [
      ...(initialPermissions?.auth_methods ?? ['fayid_ed25519', 'oauth2', 'device_fingerprint']),
    ],
  };

  return {
    schema_version: IFAY_PROFILE_SCHEMA_VERSION,
    identity: {
      fay_id: fayId,
      human_prime_id: humanPrimeId,
      entity_public_key_hex: entityPublicKeyHex,
      human_prime_public_key_hex: humanPrimePublicKeyHex,
      display_name: displayName,
      bio,
      visibility_mode: 'stealth',
      platform_registrations: [],
      created_at: createdAt,
    },
    ego: {
      active_persona_id: activePersonaId,
      personas: basePersonas,
      human_corrections: [],
    },
    thought,
    skill: skills,
    hardware,
    permissions,
  };
}

export function normalizeThoughtItem(input, defaultTimestamp = '2026-11-20T00:00:00.000Z') {
  const subtype = input.subtype ?? 'knowledge_base';
  if (!THOUGHT_SUBTYPES.includes(subtype)) {
    throw new Error(`Invalid Thought subtype '${String(subtype)}'`);
  }
  const title = String(input.title ?? '').trim();
  if (!title) {
    throw new Error('Thought item requires a non-empty title');
  }
  const textContent =
    typeof input.text === 'string'
      ? input.text
      : typeof input.summary === 'string'
        ? input.summary
        : canonicalizeJcs(input.payload ?? {});
  const contentSha256 = input.content_sha256 ?? sha256Hex(Buffer.from(textContent, 'utf8'));
  const byteSize =
    Number.isInteger(input.byte_size) && input.byte_size >= 0
      ? input.byte_size
      : Buffer.byteLength(textContent, 'utf8');
  const thoughtId = input.thought_id ?? `tht_${contentSha256.slice(0, 16)}`;

  return {
    thought_id: thoughtId,
    subtype,
    title,
    summary: String(input.summary ?? textContent.slice(0, 240)),
    text: textContent,
    domain: String(input.domain ?? 'general'),
    tags: Array.from(new Set((input.tags ?? []).map(String))),
    sensitivity: input.sensitivity ?? 'personal',
    source: input.source ?? 'primary_body',
    byte_size: byteSize,
    content_sha256: contentSha256,
    created_at: input.created_at ?? defaultTimestamp,
  };
}

export function normalizeSkillItem(input, defaultTimestamp = '2026-11-20T00:00:00.000Z') {
  const skillType = input.skill_type ?? input.type ?? 'api';
  if (!SKILL_TYPES.includes(skillType)) {
    throw new Error(`Invalid Skill type '${String(skillType)}'`);
  }
  const name = String(input.name ?? '').trim();
  if (!name) {
    throw new Error('Skill requires a non-empty name');
  }
  const skillId =
    input.skill_id ??
    `skl_${sha256Hex(`${skillType}:${name}:${input.endpoint_or_package ?? ''}`).slice(0, 16)}`;

  return {
    skill_id: skillId,
    skill_type: skillType,
    name,
    endpoint_or_package: String(input.endpoint_or_package ?? `@ifay/skill-${skillId.slice(4, 10)}`),
    domains: Array.from(new Set((input.domains ?? ['general']).map(String))),
    required_capabilities: Array.from(new Set((input.required_capabilities ?? []).map(String))),
    preauthorized: input.preauthorized !== false,
    ...(input.ssp_descriptor ? { ssp_descriptor: input.ssp_descriptor } : {}),
    registered_at: input.registered_at ?? defaultTimestamp,
  };
}

export function signPlatformRegistrationAttestation(
  {
    fayId,
    platformId,
    category = 'expert',
    handleOrRef,
    discoverable = true,
    scopes = ['profile.identity', 'skill.public'],
    registeredAt = '2026-11-20T00:00:00.000Z',
  },
  signer,
) {
  if (!PLATFORM_CATEGORIES.includes(category)) {
    throw new Error(`Invalid platform registration category '${String(category)}'`);
  }
  if (!platformId || typeof platformId !== 'string') {
    throw new Error('platformId is required');
  }
  if (!handleOrRef || typeof handleOrRef !== 'string') {
    throw new Error('handleOrRef is required');
  }
  const attestationCore = {
    schema_version: 'platform-attestation/1.0',
    attestation_id: `att_${sha256Hex(`${fayId}:${platformId}:${handleOrRef}`).slice(0, 16)}`,
    fay_id: fayId,
    platform_id: platformId,
    category,
    handle_or_ref: handleOrRef,
    discoverable: Boolean(discoverable),
    scopes: Array.from(new Set(scopes.map(String))),
    registered_at: registeredAt,
    revoked_at: null,
    signer_public_key_hex: signer.publicKeyHex,
  };
  const preimage = Buffer.from(
    `${PLATFORM_ATTESTATION_DOMAIN}\0${canonicalizeJcs(attestationCore)}`,
    'utf8',
  );
  const signatureHex = signer.signPayload(preimage).toString('hex');
  return {
    ...attestationCore,
    signature_hex: signatureHex,
  };
}

export function verifyPlatformRegistrationAttestation(attestation, trustedPublicKeyHex) {
  if (!attestation || typeof attestation !== 'object') return false;
  const pubHex = trustedPublicKeyHex ?? attestation.signer_public_key_hex;
  if (!pubHex || pubHex !== attestation.signer_public_key_hex) return false;
  const core = { ...attestation, revoked_at: null };
  delete core.signature_hex;
  const preimage = Buffer.from(`${PLATFORM_ATTESTATION_DOMAIN}\0${canonicalizeJcs(core)}`, 'utf8');
  return verifyEd25519(pubHex, preimage, attestation.signature_hex);
}

// ============================================================================
// DTP 1.0 Encrypted Personal Context Ingestion Hook
// ============================================================================

export function packDtpPersonalContextFrame(
  {
    senderFayId,
    sessionId = 'sess_dtp_context_01',
    sequenceNumber = 1,
    timestampMs = 1795166400000,
    title,
    text,
    domain = 'engineering',
    subtype = 'data',
    tags = ['dtp-ingested'],
  },
  sessionKey32,
  iv12,
) {
  const payloadObj = {
    schema: 'ifay-dtp-context/1.0',
    subtype,
    title,
    text,
    domain,
    tags,
  };
  const plaintext = Buffer.from(canonicalizeJcs(payloadObj), 'utf8');
  const header = {
    protocolVersion: { major: 1, minor: 0 },
    frameType: 'DATA_FRAGMENT',
    fragmentId: `frag_${sessionId}_${sequenceNumber}`,
    agreementId: sessionId,
    originTimestamp: timestampMs,
    dagDependencies: [],
    encryptionMetadata: {
      algorithm: 'AES-256-GCM',
      keyId: senderFayId,
    },
    sequenceNumber,
  };
  return encodeDtpFrame(header, plaintext, sessionKey32, iv12);
}

export function ingestDtpContextFrame(wireFrameBytes, sessionKey32, options = {}) {
  const decoded = decodeDtpFrame(wireFrameBytes, sessionKey32);
  if (!decoded.ok) {
    return {
      ok: false,
      errorCode: decoded.errorName,
      diagnosticCode: decoded.errorCode,
    };
  }
  let parsedContext;
  try {
    parsedContext = JSON.parse(decoded.plaintext.toString('utf8'));
  } catch (err) {
    return { ok: false, errorCode: 'INVALID_DTP_CONTEXT_JSON', reason: err.message };
  }

  const createdAt =
    options.createdAt ??
    (typeof decoded.header.originTimestamp === 'number'
      ? new Date(decoded.header.originTimestamp).toISOString()
      : '2026-11-20T00:00:00.000Z');

  const thoughtItem = normalizeThoughtItem(
    {
      subtype: parsedContext.subtype ?? 'data',
      title: parsedContext.title ?? `DTP Context #${decoded.header.sequenceNumber ?? 0}`,
      text: parsedContext.text ?? decoded.plaintext.toString('utf8'),
      domain: parsedContext.domain ?? 'general',
      tags: [...(parsedContext.tags ?? []), 'dtp_ingested'],
      source: `dtp:${decoded.header.agreementId ?? decoded.header.fragmentId ?? 'tunnel'}`,
      created_at: createdAt,
    },
    createdAt,
  );

  return {
    ok: true,
    header: decoded.header,
    thoughtItem,
  };
}

// ============================================================================
// 6-Dimension iFay Profile Validator
// ============================================================================

export function validateIfayProfile(profile) {
  const errors = [];
  if (!profile || typeof profile !== 'object') {
    return { valid: false, errors: ['PROFILE_NOT_OBJECT'] };
  }
  if (profile.schema_version !== IFAY_PROFILE_SCHEMA_VERSION) {
    errors.push('INVALID_PROFILE_SCHEMA_VERSION');
  }

  // 1. Identity
  const id = profile.identity;
  if (!id || typeof id !== 'object') {
    errors.push('MISSING_DIMENSION_IDENTITY');
  } else {
    if (!isValidFayId(id.fay_id, 'IFAY_ID')) {
      errors.push('INVALID_IDENTITY_FAY_ID');
    }
    if (!isValidFayId(id.human_prime_id, 'HUMAN_ID')) {
      errors.push('INVALID_IDENTITY_HUMAN_PRIME_ID');
    }
    if (!['stealth', 'registered_opt_in'].includes(id.visibility_mode)) {
      errors.push('INVALID_VISIBILITY_MODE');
    }
    if (!Array.isArray(id.platform_registrations)) {
      errors.push('INVALID_PLATFORM_REGISTRATIONS');
    } else {
      const allowedPubKeys = new Set(
        [id.entity_public_key_hex, id.human_prime_public_key_hex].filter(Boolean),
      );
      let anyActiveDiscoverable = false;
      for (const att of id.platform_registrations) {
        if (
          !verifyPlatformRegistrationAttestation(att) ||
          (allowedPubKeys.size > 0 && !allowedPubKeys.has(att.signer_public_key_hex))
        ) {
          errors.push(`INVALID_PLATFORM_ATTESTATION_SIGNATURE:${att?.platform_id ?? 'unknown'}`);
        }
        if (!att.revoked_at && att.discoverable) {
          anyActiveDiscoverable = true;
        }
      }
      const expectedMode = anyActiveDiscoverable ? 'registered_opt_in' : 'stealth';
      if (id.visibility_mode !== expectedMode) {
        errors.push(`VISIBILITY_MODE_MISMATCH:expected=${expectedMode}`);
      }
    }
  }

  // 2. Ego (strictly 1 active persona invariant!)
  const ego = profile.ego;
  if (!ego || typeof ego !== 'object' || !Array.isArray(ego.personas)) {
    errors.push('MISSING_DIMENSION_EGO');
  } else {
    const activePersonas = ego.personas.filter((p) => p && p.active === true);
    if (activePersonas.length !== 1) {
      errors.push(`SINGLE_ACTIVE_EGO_VIOLATION:active_count=${activePersonas.length}`);
    } else if (activePersonas[0].persona_id !== ego.active_persona_id) {
      errors.push('ACTIVE_PERSONA_ID_MISMATCH');
    }
  }

  // 3. Thought (all 4 subtypes)
  const thought = profile.thought;
  if (!thought || typeof thought !== 'object') {
    errors.push('MISSING_DIMENSION_THOUGHT');
  } else {
    for (const sub of THOUGHT_SUBTYPES) {
      if (!Array.isArray(thought[sub])) {
        errors.push(`MISSING_THOUGHT_SUBTYPE:${sub}`);
      }
    }
  }

  // 4. Skill (6 valid types)
  if (!Array.isArray(profile.skill)) {
    errors.push('MISSING_DIMENSION_SKILL');
  } else {
    for (const sk of profile.skill) {
      if (!SKILL_TYPES.includes(sk?.skill_type)) {
        errors.push(`INVALID_SKILL_TYPE:${String(sk?.skill_type)}`);
      }
    }
  }

  // 5. Hardware (3 subtypes)
  const hw = profile.hardware;
  if (!hw || typeof hw !== 'object') {
    errors.push('MISSING_DIMENSION_HARDWARE');
  } else {
    for (const sub of HARDWARE_SUBTYPES) {
      if (!Array.isArray(hw[sub])) {
        errors.push(`MISSING_HARDWARE_SUBTYPE:${sub}`);
      }
    }
  }

  // 6. Permissions (3 lifecycles)
  const perms = profile.permissions;
  if (!perms || typeof perms !== 'object') {
    errors.push('MISSING_DIMENSION_PERMISSIONS');
  } else {
    for (const lc of PERMISSION_LIFECYCLES) {
      if (!Array.isArray(perms[lc])) {
        errors.push(`MISSING_PERMISSION_LIFECYCLE:${lc}`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
