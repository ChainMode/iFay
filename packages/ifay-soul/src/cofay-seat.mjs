import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  base32EncodeNoPad,
  canonicalizeJcs,
  createFayManifest,
  deriveEntityKeypair,
  ed25519KeypairFromSeed,
  isValidFayId,
  validateFayManifest,
  verifyEd25519,
} from '@ifay/sdk';
import { packBufBinary } from './buf-codec.mjs';

export const ROLE_CHARTER_SCHEMA_VERSION = '1.0';
export const TRANSFER_ENVELOPE_VERSION = '1.0';
export const ROLE_CHARTER_SIGNING_DOMAIN = 'ifay.cofay.role-charter.v1';
export const OWNERSHIP_TRANSFER_SIGNING_DOMAIN = 'ifay.cofay.ownership-transfer.v1';

export const ROLE_ARCHETYPES = Object.freeze([
  'org_service',
  'functional_post',
  'project_collaborator',
]);

export const COFAY_LIFECYCLE_STATES = Object.freeze([
  'ACTIVE',
  'SUSPENDED_PENDING_SUCCESSION',
  'REVOKED',
]);

const FORBIDDEN_PERSONAL_EGO_KEYS = new Set([
  'ego_package',
  'ego_model',
  'ego_profile',
  'human_prime_id',
  'personal_persona',
]);

const CHARTER_ID_RE = /^chr_[a-z2-7]{16,64}$/;
const HEX32_RE = /^[0-9a-f]{64}$/;
const HEX64_RE = /^[0-9a-f]{128}$/;

function sha256Bytes(input) {
  return createHash('sha256').update(input).digest();
}

export function computeRoleCharterDigestHex(charter) {
  return createHash('sha256').update(canonicalizeJcs(charter), 'utf8').digest('hex');
}

function buildDomainSigningBytes(domain, payloadWithoutSig) {
  return Buffer.from(`${domain}\0${canonicalizeJcs(payloadWithoutSig)}`, 'utf8');
}

function normalizeSeedBuf(seedOrHex) {
  if (typeof seedOrHex === 'string') {
    if (!HEX32_RE.test(seedOrHex.toLowerCase())) {
      throw new TypeError('Ed25519 seed hex must be 64 hex characters (32 bytes)');
    }
    return Buffer.from(seedOrHex, 'hex');
  }
  const b = Buffer.from(seedOrHex);
  if (b.length !== 32) {
    throw new RangeError('Ed25519 seed must be 32 bytes');
  }
  return b;
}

export function deriveCharterId(cofayId, revision = 1) {
  const digest = sha256Bytes(`${cofayId}:rev:${revision}`);
  return `chr_${base32EncodeNoPad(digest.subarray(0, 20))}`;
}

const ARCHETYPE_PRESETS = Object.freeze({
  org_service: {
    display_name: 'Organization Service Seat',
    mission_statement:
      'Operate accountable public-facing organizational customer and partner service workflows without personal Ego bias.',
    allowed_capabilities: {
      ssp_skills: [
        {
          skill_ref: 'ssp://org.service/ticket-triage-v1',
          visibility: 'public',
          require_caller_auth: false,
        },
        {
          skill_ref: 'ssp://org.service/sla-escalation-v1',
          visibility: 'restricted',
          require_caller_auth: true,
        },
      ],
      cap_bounds: {
        allowed_scopes: ['fs.read', 'net.http'],
        max_autonomy_tier: 'official_post',
        allow_irreversible_actions: false,
      },
    },
    prohibited_actions: [
      'Never impersonate a natural person or attach a personal Ego model',
      'Never approve unbudgeted financial disbursements without steward sign-off',
    ],
  },
  functional_post: {
    display_name: 'Functional Governance Post Seat',
    mission_statement:
      'Execute standing release-gate, compliance auditing, and operational stewardship duties with rotational steward continuity.',
    allowed_capabilities: {
      ssp_skills: [
        {
          skill_ref: 'ssp://org.post/compliance-audit-v1',
          visibility: 'restricted',
          require_caller_auth: true,
        },
      ],
      cap_bounds: {
        allowed_scopes: ['fs.read', 'crypto.hash'],
        max_autonomy_tier: 'delegated',
        allow_irreversible_actions: false,
      },
    },
    prohibited_actions: [
      'Never bypass charter audit logging or actor attribution',
      'Never re-delegate manager authority beyond single-hop charter bounds',
    ],
  },
  project_collaborator: {
    display_name: 'Open-Source Project Collaborator Seat',
    mission_statement:
      'Coordinate multi-contributor repository triage, specification review, and conformance verification under a public RoleCharter.',
    allowed_capabilities: {
      ssp_skills: [
        {
          skill_ref: 'ssp://oss.collab/pr-conformance-check-v1',
          visibility: 'public',
          require_caller_auth: false,
        },
        {
          skill_ref: 'ssp://oss.collab/release-notes-draft-v1',
          visibility: 'restricted',
          require_caller_auth: true,
        },
      ],
      cap_bounds: {
        allowed_scopes: ['fs.read', 'fs.write', 'crypto.hash'],
        max_autonomy_tier: 'delegated',
        allow_irreversible_actions: false,
      },
    },
    prohibited_actions: [
      'Never force-push protected branches or delete release tags',
      'Never embed private Human Prime persona weights into public seat artifacts',
    ],
  },
});

export function signRoleCharter(unsignedCharter, { signerId, signerSeed }) {
  const kp = ed25519KeypairFromSeed(normalizeSeedBuf(signerSeed));
  const payload = { ...unsignedCharter };
  delete payload.owner_signature;

  const signingBytes = buildDomainSigningBytes(ROLE_CHARTER_SIGNING_DOMAIN, payload);
  const sigHex = kp.signPayload(signingBytes).toString('hex');

  const signed = {
    ...payload,
    owner_signature: {
      alg: 'Ed25519',
      domain: ROLE_CHARTER_SIGNING_DOMAIN,
      signer_id: signerId,
      public_key_hex: kp.publicKeyHex,
      signature_hex: sigHex,
    },
  };
  const check = validateRoleCharter(signed);
  if (!check.valid) {
    throw new Error(`Invalid RoleCharter 1.0: ${check.errors.map((e) => e.code).join(', ')}`);
  }
  return signed;
}

export function validateRoleCharter(charter, options = {}) {
  const { verifySignature = true } = options;
  const errors = [];
  if (!charter || typeof charter !== 'object' || Array.isArray(charter)) {
    return { valid: false, errors: [{ code: 'CHARTER_NOT_OBJECT', message: 'Not an object' }] };
  }

  for (const key of Object.keys(charter)) {
    if (FORBIDDEN_PERSONAL_EGO_KEYS.has(key)) {
      errors.push({
        code: 'COFAY_EGO_FORBIDDEN',
        field: key,
        message: `coFay possesses no Ego layer; '${key}' is forbidden.`,
      });
    }
  }

  if (charter.schema_version !== ROLE_CHARTER_SCHEMA_VERSION) {
    errors.push({ code: 'SCHEMA_VERSION_INVALID', field: 'schema_version', message: 'Expected 1.0' });
  }
  if (typeof charter.charter_id !== 'string' || !CHARTER_ID_RE.test(charter.charter_id)) {
    errors.push({ code: 'CHARTER_ID_INVALID', field: 'charter_id', message: 'Malformed charter_id' });
  }
  if (!Number.isInteger(charter.charter_revision) || charter.charter_revision < 1) {
    errors.push({ code: 'CHARTER_REVISION_INVALID', field: 'charter_revision', message: 'Invalid rev' });
  }
  if (!isValidFayId(charter.cofay_id, 'COFAY_ID')) {
    errors.push({ code: 'COFAY_ID_INVALID', field: 'cofay_id', message: 'Expected cofay_<base32>' });
  }
  if (!ROLE_ARCHETYPES.includes(charter.role_archetype)) {
    errors.push({ code: 'ROLE_ARCHETYPE_INVALID', field: 'role_archetype', message: 'Invalid archetype' });
  }

  const owner = charter.owner;
  if (!owner || typeof owner !== 'object') {
    errors.push({ code: 'OWNER_INVALID', field: 'owner', message: 'Missing owner' });
  } else if (owner.type === 'human') {
    if (!isValidFayId(owner.id, 'HUMAN_ID')) {
      errors.push({ code: 'OWNER_TYPE_FORBIDDEN', field: 'owner.id', message: 'Expected hid_' });
    }
    if (charter.steward_human_id !== undefined && charter.steward_human_id !== owner.id) {
      errors.push({ code: 'HUMAN_STEWARD_MISMATCH', field: 'steward_human_id', message: 'Mismatch' });
    }
  } else if (owner.type === 'organization') {
    if (!isValidFayId(owner.id, 'ORGANIZATION_ID')) {
      errors.push({ code: 'OWNER_TYPE_FORBIDDEN', field: 'owner.id', message: 'Expected org_' });
    }
    if (!isValidFayId(charter.steward_human_id, 'HUMAN_ID')) {
      errors.push({
        code: 'ORG_STEWARD_REQUIRED',
        field: 'steward_human_id',
        message: 'Organization coFay requires natural-person steward_human_id',
      });
    }
  } else {
    errors.push({ code: 'OWNER_TYPE_FORBIDDEN', field: 'owner.type', message: 'Invalid owner.type' });
  }

  if (!Array.isArray(charter.managers)) {
    errors.push({ code: 'MANAGERS_INVALID', field: 'managers', message: 'Expected array' });
  } else {
    const seen = new Set();
    for (const m of charter.managers) {
      if (!isValidFayId(m, 'IFAY_ID') || seen.has(m)) {
        errors.push({ code: 'MANAGER_ID_INVALID', field: 'managers', message: `Invalid manager ${m}` });
      }
      seen.add(m);
    }
  }

  if (!COFAY_LIFECYCLE_STATES.includes(charter.lifecycle_state)) {
    errors.push({ code: 'LIFECYCLE_STATE_INVALID', field: 'lifecycle_state', message: 'Invalid state' });
  }
  if (!Number.isInteger(charter.transfer_nonce) || charter.transfer_nonce < 0) {
    errors.push({ code: 'TRANSFER_NONCE_INVALID', field: 'transfer_nonce', message: 'Invalid nonce' });
  }
  if (charter.audit_policy?.require_actor_trace !== true) {
    errors.push({ code: 'AUDIT_ACTOR_TRACE_REQUIRED', field: 'audit_policy', message: 'Trace required' });
  }

  if (verifySignature) {
    const sig = charter.owner_signature;
    const allowedSigners = new Set([charter.owner?.id, charter.steward_human_id].filter(Boolean));
    if (
      !sig ||
      sig.alg !== 'Ed25519' ||
      sig.domain !== ROLE_CHARTER_SIGNING_DOMAIN ||
      !allowedSigners.has(sig.signer_id) ||
      !HEX32_RE.test(sig.public_key_hex ?? '') ||
      !HEX64_RE.test(sig.signature_hex ?? '')
    ) {
      errors.push({ code: 'CHARTER_SIGNATURE_INVALID', field: 'owner_signature', message: 'Malformed sig' });
    } else {
      const payload = { ...charter };
      delete payload.owner_signature;
      const signingBytes = buildDomainSigningBytes(ROLE_CHARTER_SIGNING_DOMAIN, payload);
      if (!verifyEd25519(sig.public_key_hex, signingBytes, sig.signature_hex)) {
        errors.push({
          code: 'CHARTER_SIGNATURE_INVALID',
          field: 'owner_signature',
          message: 'Ed25519 verification failed',
        });
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

export class CofaySeatBuilder {
  static createSeat(options = {}) {
    const archetype = options.roleArchetype ?? 'project_collaborator';
    if (!ROLE_ARCHETYPES.includes(archetype)) {
      throw new Error(`Invalid roleArchetype '${archetype}'`);
    }
    const preset = ARCHETYPE_PRESETS[archetype];
    const masterSeed = options.masterSeed ? normalizeSeedBuf(options.masterSeed) : randomBytes(32);

    const cofayKp = deriveEntityKeypair(masterSeed, 'cofay', options.seatSlot ?? 0);
    if (!cofayKp.ok) throw new Error(cofayKp.error);

    const stewardKp = deriveEntityKeypair(masterSeed, 'hid', options.stewardSlot ?? 0);
    if (!stewardKp.ok) throw new Error(stewardKp.error);

    const ownerType = options.ownerType ?? 'organization';
    let owner;
    let stewardHumanId;
    if (ownerType === 'organization') {
      const orgSlug = options.orgSlug ?? 'ifay-community';
      const orgKp = deriveEntityKeypair(masterSeed, 'org', orgSlug);
      if (!orgKp.ok) throw new Error(orgKp.error);
      owner = { type: 'organization', id: orgKp.value.entityId };
      stewardHumanId = options.stewardHumanId ?? stewardKp.value.entityId;
    } else {
      const humanId = options.ownerHumanId ?? stewardKp.value.entityId;
      owner = { type: 'human', id: humanId };
      stewardHumanId = humanId;
    }

    const issuedAt = options.issuedAt ?? '2026-11-20T00:00:00.000Z';
    const cofayId = options.cofayId ?? cofayKp.value.entityId;
    const signerSeed = options.signerSeed ? normalizeSeedBuf(options.signerSeed) : masterSeed;
    const signerId = options.signerId ?? stewardHumanId;

    const unsignedCharter = {
      schema_version: ROLE_CHARTER_SCHEMA_VERSION,
      charter_id: deriveCharterId(cofayId, 1),
      charter_revision: 1,
      cofay_id: cofayId,
      display_name: options.displayName ?? preset.display_name,
      role_archetype: archetype,
      owner,
      ...(owner.type === 'organization' ? { steward_human_id: stewardHumanId } : {}),
      managers: [...(options.managers ?? [])],
      mission_statement: options.missionStatement ?? preset.mission_statement,
      allowed_capabilities: options.allowedCapabilities ?? structuredClone(preset.allowed_capabilities),
      prohibited_actions: options.prohibitedActions ?? [...preset.prohibited_actions],
      audit_policy: {
        retention_days: options.retentionDays ?? 365,
        log_mode: 'hash_chain',
        require_actor_trace: true,
        ...(options.meritPocketRef ? { gmc_merit_pocket_ref: options.meritPocketRef } : {}),
      },
      lifecycle_state: 'ACTIVE',
      transfer_nonce: 0,
      issued_at: issuedAt,
    };

    const roleCharter = signRoleCharter(unsignedCharter, {
      signerId,
      signerSeed,
    });

    const fayManifest = createFayManifest({
      name: (options.manifestName ?? `cofay-${archetype.replace(/_/g, '-')}-seat`).toLowerCase(),
      version: '1.0.0',
      description: roleCharter.mission_statement,
      vendor: owner.id,
      fayId: cofayId,
      controlMode: 'command',
      modules: [
        { id: 'registered_skill', version: '^1.0.0' },
        { id: 'invoke_skill', version: '^1.0.0' },
      ],
      protocols: [
        { id: 'ssp_protocol', version: '^1.0.0' },
        { id: 'cap_protocol', version: '^1.0.0' },
        { id: 'icp_protocol', version: '^1.0.0' },
      ],
      permissions: {
        inherent: ['charter.read', 'audit.append'],
        persistent: roleCharter.allowed_capabilities.cap_bounds.allowed_scopes,
        authMethods: ['fayid_ed25519'],
      },
    });
    const manifestValidation = validateFayManifest(fayManifest);
    if (!manifestValidation.valid) {
      throw new Error(`coFay FayManifest invalid: ${manifestValidation.errors.join('; ')}`);
    }

    return {
      seat_type: 'cofay',
      cofay_id: cofayId,
      role_charter: roleCharter,
      charter_digest_hex: computeRoleCharterDigestHex(roleCharter),
      fay_manifest: fayManifest,
    };
  }

  static rotateSteward(currentCharter, { newStewardHumanId, ownerOrCurrentSignerId, signerSeed, issuedAt }) {
    const check = validateRoleCharter(currentCharter);
    if (!check.valid) {
      throw new Error(`Current charter invalid: ${check.errors.map((e) => e.code).join(', ')}`);
    }
    if (currentCharter.owner.type !== 'organization') {
      throw new Error('Steward rotation applies to organization-owned coFay seats; use ownership transfer for human owner changes');
    }
    if (!isValidFayId(newStewardHumanId, 'HUMAN_ID')) {
      throw new Error('newStewardHumanId must be a canonical hid_<base32> Human ID');
    }
    const nextRevision = currentCharter.charter_revision + 1;
    const unsignedNext = {
      ...currentCharter,
      charter_id: deriveCharterId(currentCharter.cofay_id, nextRevision),
      charter_revision: nextRevision,
      steward_human_id: newStewardHumanId,
      issued_at: issuedAt ?? '2026-11-20T01:00:00.000Z',
    };
    delete unsignedNext.owner_signature;

    // Sign with the incoming steward or organization owner key
    const effectiveSigner = ownerOrCurrentSignerId ?? currentCharter.owner.id;
    return signRoleCharter(unsignedNext, {
      signerId: effectiveSigner,
      signerSeed,
    });
  }

  static createTransferEnvelope(
    currentCharter,
    {
      toOwner,
      newStewardHumanId,
      managerPolicy = 'CLEAR_ALL',
      ratifiedManagers = [],
      initiatedAt = '2026-11-20T02:00:00.000Z',
      expiresAt = '2026-11-21T02:00:00.000Z',
      fromSignerId,
      fromSeed,
      toSignerId,
      toSeed,
    },
  ) {
    const check = validateRoleCharter(currentCharter);
    if (!check.valid) {
      throw new Error(`Cannot transfer invalid RoleCharter: ${check.errors.map((e) => e.code).join(', ')}`);
    }
    const unsignedEnvelope = {
      envelope_version: TRANSFER_ENVELOPE_VERSION,
      cofay_id: currentCharter.cofay_id,
      prior_charter_digest_hex: computeRoleCharterDigestHex(currentCharter),
      transfer_nonce: currentCharter.transfer_nonce + 1,
      from_owner: structuredClone(currentCharter.owner),
      to_owner: structuredClone(toOwner),
      ...(toOwner.type === 'organization' ? { new_steward_human_id: newStewardHumanId } : {}),
      manager_policy: managerPolicy,
      ratified_managers: managerPolicy === 'CLEAR_ALL' ? [] : [...ratifiedManagers],
      merit_continuity: {
        preserve_cofay_id: true,
        preserve_merit_pocket: true,
      },
      initiated_at: initiatedAt,
      expires_at: expiresAt,
    };

    const signingBytes = buildDomainSigningBytes(OWNERSHIP_TRANSFER_SIGNING_DOMAIN, unsignedEnvelope);
    const fromKp = ed25519KeypairFromSeed(normalizeSeedBuf(fromSeed));
    const toKp = ed25519KeypairFromSeed(normalizeSeedBuf(toSeed));

    const resolvedFromSigner = fromSignerId ?? currentCharter.steward_human_id ?? currentCharter.owner.id;
    const resolvedToSigner =
      toSignerId ?? (toOwner.type === 'organization' ? newStewardHumanId : toOwner.id);

    return {
      ...unsignedEnvelope,
      from_signature: {
        alg: 'Ed25519',
        domain: OWNERSHIP_TRANSFER_SIGNING_DOMAIN,
        signer_id: resolvedFromSigner,
        public_key_hex: fromKp.publicKeyHex,
        signature_hex: fromKp.signPayload(signingBytes).toString('hex'),
      },
      to_signature: {
        alg: 'Ed25519',
        domain: OWNERSHIP_TRANSFER_SIGNING_DOMAIN,
        signer_id: resolvedToSigner,
        public_key_hex: toKp.publicKeyHex,
        signature_hex: toKp.signPayload(signingBytes).toString('hex'),
      },
    };
  }

  static applyOwnershipTransfer(currentCharter, envelope, { nextOwnerSignerId, nextOwnerSeed } = {}) {
    const errors = [];
    const currentCheck = validateRoleCharter(currentCharter);
    if (!currentCheck.valid) {
      return { valid: false, errors: currentCheck.errors };
    }
    if (currentCharter.lifecycle_state === 'REVOKED') {
      return {
        valid: false,
        errors: [{ code: 'CHARTER_REVOKED_NOT_TRANSFERABLE', message: 'Revoked charter' }],
      };
    }
    if (!envelope || envelope.envelope_version !== TRANSFER_ENVELOPE_VERSION) {
      errors.push({ code: 'TRANSFER_VERSION_INVALID', message: 'Expected TransferEnvelope 1.0' });
    }
    if (envelope.cofay_id !== currentCharter.cofay_id) {
      errors.push({ code: 'TRANSFER_COFAY_MISMATCH', message: 'cofay_id mismatch' });
    }
    if (envelope.prior_charter_digest_hex !== computeRoleCharterDigestHex(currentCharter)) {
      errors.push({ code: 'PRIOR_CHARTER_DIGEST_MISMATCH', message: 'prior digest mismatch' });
    }
    if (envelope.transfer_nonce !== currentCharter.transfer_nonce + 1) {
      errors.push({ code: 'TRANSFER_NONCE_MISMATCH', message: 'Non-monotonic transfer_nonce' });
    }
    if (
      envelope.from_owner?.type !== currentCharter.owner.type ||
      envelope.from_owner?.id !== currentCharter.owner.id
    ) {
      errors.push({ code: 'TRANSFER_FROM_OWNER_MISMATCH', message: 'from_owner mismatch' });
    }
    if (
      envelope.from_owner?.type === envelope.to_owner?.type &&
      envelope.from_owner?.id === envelope.to_owner?.id
    ) {
      errors.push({ code: 'SELF_TRANSFER_REDUNDANT', message: 'Self transfer forbidden' });
    }
    if (
      envelope.merit_continuity?.preserve_cofay_id !== true ||
      envelope.merit_continuity?.preserve_merit_pocket !== true
    ) {
      errors.push({ code: 'MERIT_CONTINUITY_VIOLATION', message: 'Must preserve cofay_id & merit pocket' });
    }
    if (envelope.manager_policy === 'CLEAR_ALL' && (envelope.ratified_managers?.length ?? 0) > 0) {
      errors.push({ code: 'CLEAR_ALL_NON_EMPTY_MANAGERS', message: 'Expected empty ratified_managers' });
    }

    const payloadWithoutSigs = { ...envelope };
    delete payloadWithoutSigs.from_signature;
    delete payloadWithoutSigs.to_signature;
    const signingBytes = buildDomainSigningBytes(OWNERSHIP_TRANSFER_SIGNING_DOMAIN, payloadWithoutSigs);

    const expectedFromSigners = new Set(
      [currentCharter.owner.id, currentCharter.steward_human_id].filter(Boolean),
    );
    const expectedToSigners = new Set(
      [envelope.to_owner?.id, envelope.new_steward_human_id].filter(Boolean),
    );

    for (const [label, sig, allowed] of [
      ['from_signature', envelope.from_signature, expectedFromSigners],
      ['to_signature', envelope.to_signature, expectedToSigners],
    ]) {
      if (!sig) {
        errors.push({ code: 'TRANSFER_DUAL_SIGNATURE_REQUIRED', field: label, message: `Missing ${label}` });
      } else if (
        sig.alg !== 'Ed25519' ||
        sig.domain !== OWNERSHIP_TRANSFER_SIGNING_DOMAIN ||
        !allowed.has(sig.signer_id) ||
        !verifyEd25519(sig.public_key_hex, signingBytes, sig.signature_hex)
      ) {
        errors.push({ code: 'TRANSFER_SIGNATURE_INVALID', field: label, message: `Invalid ${label}` });
      }
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    const nextRevision = currentCharter.charter_revision + 1;
    const unsignedNext = {
      ...currentCharter,
      charter_id: deriveCharterId(currentCharter.cofay_id, nextRevision),
      charter_revision: nextRevision,
      owner: structuredClone(envelope.to_owner),
      managers: envelope.manager_policy === 'CLEAR_ALL' ? [] : [...envelope.ratified_managers],
      transfer_nonce: envelope.transfer_nonce,
      issued_at: envelope.initiated_at,
      lifecycle_state: 'ACTIVE',
    };
    delete unsignedNext.owner_signature;
    if (envelope.to_owner.type === 'organization') {
      unsignedNext.steward_human_id = envelope.new_steward_human_id;
    } else {
      delete unsignedNext.steward_human_id;
    }

    if (nextOwnerSeed) {
      const signerId =
        nextOwnerSignerId ??
        (envelope.to_owner.type === 'organization'
          ? envelope.new_steward_human_id
          : envelope.to_owner.id);
      const signedNext = signRoleCharter(unsignedNext, {
        signerId,
        signerSeed: nextOwnerSeed,
      });
      return { valid: true, errors: [], nextCharter: signedNext };
    }
    return { valid: true, errors: [], nextCharter: unsignedNext };
  }

  static packSeatBuf(seat, options = {}) {
    const charterBytes = Buffer.from(canonicalizeJcs(seat.role_charter), 'utf8');
    const manifestBytes = Buffer.from(canonicalizeJcs(seat.fay_manifest), 'utf8');
    const entryTaskIr = {
      schema_version: 'fayger-task-ir/1.0',
      entity_kind: 'cofay',
      cofay_id: seat.cofay_id,
      role_archetype: seat.role_charter.role_archetype,
      steps: [],
    };
    const requestedCaps = seat.role_charter.allowed_capabilities.cap_bounds.allowed_scopes ?? [];
    const grantedCaps = options.grantedCapabilities ?? requestedCaps;
    const negotiatedCaps = requestedCaps.filter((c) => grantedCaps.includes(c));

    return packBufBinary({
      schemaVersion: '1.0.0',
      runtimeInterfaceMin: '1.0.0',
      entry: 'main',
      capabilities: negotiatedCaps,
      quotas: options.quotas ?? {
        cpu_ms_per_sec: 250,
        memory_bytes: 256 * 1024 * 1024,
      },
      extensions: {
        fay_entity_kind: 'cofay',
        fay_id: seat.cofay_id,
        role_archetype: seat.role_charter.role_archetype,
        charter_digest_sha256: seat.charter_digest_hex ?? computeRoleCharterDigestHex(seat.role_charter),
      },
      sections: [
        {
          id: 'code',
          kind: 'code',
          visibility: 'required',
          payload: Buffer.from(canonicalizeJcs(entryTaskIr), 'utf8'),
        },
        {
          id: 'fay_manifest',
          kind: 'data',
          visibility: 'required',
          payload: manifestBytes,
        },
        {
          id: 'role_charter',
          kind: 'data',
          visibility: 'required',
          payload: charterBytes,
        },
      ],
      ...(options.signer ? { signer: options.signer } : {}),
    });
  }

  static saveToDirectory(dirPath, seat, options = {}) {
    const abs = resolve(dirPath);
    mkdirSync(abs, { recursive: true });
    writeFileSync(join(abs, 'cofay-seat.json'), `${JSON.stringify(seat, null, 2)}\n`, 'utf8');
    writeFileSync(
      join(abs, 'role-charter.json'),
      `${JSON.stringify(seat.role_charter, null, 2)}\n`,
      'utf8',
    );
    writeFileSync(
      join(abs, 'faymanifest.json'),
      `${JSON.stringify(seat.fay_manifest, null, 2)}\n`,
      'utf8',
    );
    const bufBytes = CofaySeatBuilder.packSeatBuf(seat, options);
    writeFileSync(join(abs, 'seat.buf'), bufBytes);
    return { dirPath: abs, bufPath: join(abs, 'seat.buf'), bufByteLength: bufBytes.length };
  }

  static loadFromDirectory(dirPath) {
    const abs = resolve(dirPath);
    const seatPath = join(abs, 'cofay-seat.json');
    if (!existsSync(seatPath)) {
      throw new Error(`No cofay-seat.json found in ${abs}`);
    }
    const seat = JSON.parse(readFileSync(seatPath, 'utf8'));
    const check = validateRoleCharter(seat.role_charter);
    if (!check.valid) {
      throw new Error(`Invalid RoleCharter in ${abs}: ${check.errors.map((e) => e.code).join(', ')}`);
    }
    return seat;
  }
}
