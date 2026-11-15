import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SUBKEY_DOMAINS,
  canonicalizeJcs,
  parseFayId,
  isValidFayId,
  derivePurposeSubkey,
  deriveEntityKeypair,
  deriveEgoPackageSigningKey,
  verifyEgoPackageEnvelope,
  deriveBlindGmcRef,
  ed25519KeypairFromSeed,
  signEd25519,
  verifyEd25519,
  createFayingMandate,
  verifyFayingMandate,
  triggerG0EmergencyTakeover,
  toCapMandateBinding,
  createFayManifest,
  validateFayManifest,
  resolveFayManifestDependencies,
  classifyFayManifestPhase,
  signCapDriverManifest,
  computeCapParamsSha256,
  evaluateCapAction,
  signSkillDescriptor,
  verifySkillDescriptor,
  isSspVersionCompatible,
  encodeDtpFrame,
  decodeDtpFrame,
  signEgoVaultManifest,
  verifyEgoVaultManifest,
  validateEgoFidelityPrivacy,
} from '../../ifay-sdk/src/index.mjs';

export const IFACTS_REPORT_FORMAT = 'ifacts-report/1.0';
export const COFAY_BOUNDARY_ERROR_CODE = 'COFAY_OUT_OF_SCOPE_USE_COFACTS';

const PACKAGE_ROOT = fileURLToPath(new URL('..', import.meta.url));
const IFAY_REPO_ROOT = resolve(PACKAGE_ROOT, '../..');
const WORKSPACE_SIBLING_ROOT = resolve(IFAY_REPO_ROOT, '..');
const DETERMINISTIC_SEED = Buffer.from(
  '2424242424242424242424242424242424242424242424242424242424242424',
  'hex',
);

// ============================================================================
// SHA-256 Hash-Chained Audit Trail (L3)
// ============================================================================

export function createAuditHashChain() {
  const chain = [];
  return {
    append(stage, payload, timestamp = '2026-11-16T00:00:00Z') {
      const index = chain.length;
      const prevHash = index === 0 ? '0'.repeat(64) : chain[index - 1].entryHash;
      const core = { index, timestamp, stage, payload, prevHash };
      const entryHash = createHash('sha256')
        .update(canonicalizeJcs(core), 'utf8')
        .digest('hex');
      const record = { ...core, entryHash };
      chain.push(record);
      return record;
    },
    entries() {
      return structuredClone(chain);
    },
  };
}

export function verifyAuditHashChain(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    return { valid: false, brokenIndex: 0, reason: 'Audit chain is empty' };
  }
  for (let i = 0; i < entries.length; i += 1) {
    const item = entries[i];
    const expectedPrev = i === 0 ? '0'.repeat(64) : entries[i - 1].entryHash;
    if (item.prevHash !== expectedPrev) {
      return { valid: false, brokenIndex: i, reason: 'prevHash continuity mismatch' };
    }
    const core = {
      index: item.index,
      timestamp: item.timestamp,
      stage: item.stage,
      payload: item.payload,
      prevHash: item.prevHash,
    };
    const recomputed = createHash('sha256')
      .update(canonicalizeJcs(core), 'utf8')
      .digest('hex');
    if (recomputed !== item.entryHash) {
      return { valid: false, brokenIndex: i, reason: 'entryHash digest mismatch' };
    }
  }
  return { valid: true, length: entries.length, headHash: entries[entries.length - 1].entryHash };
}

// ============================================================================
// L1: Single-Component Conformance (FayManifest, FayID, Ego Vault)
// ============================================================================

export function runL1Conformance(options = {}) {
  const checks = [];
  const recordCheck = (id, component, passed, detail) => {
    checks.push({ id, component, passed: Boolean(passed), detail });
  };

  // 1. Official FayManifest fixtures validation
  const minimalFixturePath = join(
    IFAY_REPO_ROOT,
    'schema/faymanifest/examples/minimal.faymanifest.json',
  );
  const droneFixturePath = join(
    IFAY_REPO_ROOT,
    'schema/faymanifest/examples/drone-controller.faymanifest.json',
  );
  const minimalManifest = JSON.parse(readFileSync(minimalFixturePath, 'utf8'));
  const droneManifest = JSON.parse(readFileSync(droneFixturePath, 'utf8'));
  const minVal = validateFayManifest(minimalManifest);
  const droneVal = validateFayManifest(droneManifest);
  recordCheck(
    'L1-FAYMANIFEST-OFFICIAL-FIXTURES',
    'FayManifest',
    minVal.valid && droneVal.valid,
    minVal.valid && droneVal.valid
      ? 'Official minimal and drone-controller fixtures conform to faymanifest.schema.json'
      : [...minVal.errors, ...droneVal.errors].join('; '),
  );

  // 1b. Negative FayManifest structural rejection check
  const invalidManifestVal = validateFayManifest({
    ...minimalManifest,
    unknownTopLevelField: true,
  });
  recordCheck(
    'L1-FAYMANIFEST-NEGATIVE-REJECTION',
    'FayManifest',
    !invalidManifestVal.valid,
    !invalidManifestVal.valid
      ? 'Malformed FayManifest with unknown top-level field strictly rejected'
      : 'Expected malformed FayManifest to be rejected',
  );

  // 2. Target FayManifest validation (if supplied)
  if (options.manifest) {
    const targetVal = validateFayManifest(options.manifest);
    recordCheck(
      'L1-FAYMANIFEST-TARGET',
      'FayManifest',
      targetVal.valid,
      targetVal.valid ? `Target manifest '${options.manifest.name}' valid` : targetVal.errors.join('; '),
    );
  }

  // 3. FayID canonical Base32 & prefix grammar check
  const hp = deriveEntityKeypair(DETERMINISTIC_SEED, 'hid', 0).value;
  const ifay = deriveEntityKeypair(DETERMINISTIC_SEED, 'ifay', 0).value;
  const malformedRejected = !isValidFayId('ifay_INVALID==') && !isValidFayId('unknown_12345');
  recordCheck(
    'L1-FAYID-CANONICAL-GRAMMAR',
    'FayID',
    isValidFayId(hp.entityId, 'HUMAN_ID') &&
      isValidFayId(ifay.entityId, 'IFAY_ID') &&
      malformedRejected,
    'Canonical RFC 4648 lowercase no-pad Base32 identifiers verified and malformed strings rejected',
  );

  // 4. FayID HKDF-SHA256 subkey isolation & Ed25519 Holder-of-Key check
  const egoSub = deriveEgoPackageSigningKey(DETERMINISTIC_SEED, ifay.entityId, 0).value;
  const msg = Buffer.from('ifacts-l1-hok-challenge', 'utf8');
  const sig = ifay.signPayload(msg);
  const hokOk =
    ifay.publicKeyHex !== egoSub.publicKeyHex &&
    verifyEd25519(ifay.publicKeyRaw, msg, sig) &&
    !verifyEd25519(egoSub.publicKeyRaw, msg, sig);
  recordCheck(
    'L1-FAYID-HKDF-ISOLATION-AND-HOK',
    'FayID',
    hokOk,
    'Domain-separated HKDF-SHA256 subkeys and Ed25519 Holder-of-Key signatures verified',
  );

  // 5 & 6. Ego two-tier signed manifest.json + fidelity_report privacy hygiene
  const baseEgoManifest = {
    version: '1.0.0',
    created_at: '2026-11-16T00:00:00Z',
    base_model: 'qwen3.5-0.8B',
    editions: ['normal'],
    training_backend: 'mlx',
    fidelity_report: {
      schema_version: '1.0',
      status: 'measured',
      holdout_sample_count: 48,
      holdout_loss: 1.09,
      holdout_perplexity: 2.97,
      cell_consistency_score: 0.93,
      probe_win_rate: 0.89,
      drift_from_baseline: 0.06,
    },
    integrity: {
      schema_version: '1.0',
      base_model_digest: 'unverified_offline',
      cell_digests: {
        'normal/adapters/ego-lora.safetensors':
          'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      },
    },
    ...(options.egoManifestOverride ?? {}),
  };

  let signedEgo = signEgoVaultManifest(baseEgoManifest, {
    masterSeed: DETERMINISTIC_SEED,
    signerFayId: ifay.entityId,
  });
  if (options.tamperEgoSignature) {
    signedEgo = {
      ...signedEgo,
      base_model: 'tampered-model-after-signing',
    };
  }

  const privacyRes = validateEgoFidelityPrivacy(signedEgo.fidelity_report);
  recordCheck(
    'L1-EGO-PRIVACY-HYGIENE',
    'Ego',
    privacyRes.valid,
    privacyRes.valid
      ? 'Ego fidelity_report contains strictly scalar metrics and zero raw text'
      : `Ego fidelity_report failed privacy hygiene: ${privacyRes.errorCode}`,
  );

  const egoSigRes = verifyEgoVaultManifest(signedEgo, {
    trustedPublicKeyHex: signedEgo.signature.public_key_hex,
  });
  recordCheck(
    'L1-EGO-TWO-TIER-SIGNATURE',
    'Ego',
    egoSigRes.valid,
    egoSigRes.valid
      ? 'Ego two-tier manifest.json JCS + Ed25519 signature and cell digest map verified'
      : `Ego manifest verification failed: ${egoSigRes.errorCode}`,
  );

  const passedCount = checks.filter((c) => c.passed).length;
  const failedCount = checks.length - passedCount;
  return {
    level: 'L1',
    status: failedCount === 0 ? 'passed' : 'failed',
    passedCount,
    failedCount,
    checks,
  };
}

// ============================================================================
// L2: Cross-Protocol Interface Conformance (CAP, DTP, FayID, SSP, Faying)
// ============================================================================

function buildFallbackCapSuite() {
  const anchorSeed = Buffer.alloc(32, 0x31);
  const anchorKp = ed25519KeypairFromSeed(anchorSeed);
  const trust_anchors = {
    key_trust_anchor_fallback: {
      algorithm: 'Ed25519',
      public_key_raw_hex: anchorKp.publicKeyHex,
    },
  };
  const reference_manifest = signCapDriverManifest(
    {
      manifest_id: 'mf_fallback_001',
      driver_id: 'drv_fallback_v1',
      version: '1.0.0',
      issued_at: '2026-11-16T00:00:00Z',
      signer_key_id: 'key_trust_anchor_fallback',
      resources: [
        {
          resource_id: 'res_drone_fc',
          safe_states: [{ safe_state_id: 'hover_and_rtl', description: 'Hover and RTL' }],
          operations: [
            {
              operation_id: 'read_telemetry',
              mode: 'read',
              criticality: 'routine',
              consequence_irreversibility: 'reversible',
              domain_category: 'device_control',
            },
            {
              operation_id: 'unlock_cargo_latch',
              mode: 'execute',
              criticality: 'sensitive',
              consequence_irreversibility: 'irreversible_consequence',
              domain_category: 'device_control',
            },
          ],
        },
      ],
    },
    anchorSeed,
  );
  const latchParams = { latch_id: 'bay_alpha' };
  const latchHash = computeCapParamsSha256(latchParams);
  return {
    trust_anchors,
    reference_manifest,
    vectors: [
      {
        id: 'FB_CAP_01_ALLOW_ROUTINE',
        use_reference_manifest: true,
        request_overrides: {
          request_id: 'fb_1',
          resource_id: 'res_drone_fc',
          operation_id: 'read_telemetry',
          requested_mode: 'read',
          params: {},
          grant: {
            grant_id: 'grt_fb_1',
            resource_id: 'res_drone_fc',
            allowed_modes: ['read'],
            min_grade: 'G3',
            mandate_binding: {
              mandate_id: 'mnd_fb_1',
              fay_id: 'ifay_aaaaaaaabbbbbbbbccccccccdddddddd',
              resource_id: 'res_drone_fc',
              allowed_modes: ['read'],
              session_grade: 'G3',
              binding_model: 'model_b_online_ref',
              online_fresh: true,
              revoked: false,
              expires_at_epoch_ms: 1800000060000,
            },
          },
        },
        expected: {
          decision: 'ALLOW',
          effective_criticality: 'routine',
          effective_grade: 'G3',
          escalation_clamped: false,
        },
      },
      {
        id: 'FB_CAP_02_UNKNOWN_CRITICAL_DENY',
        use_reference_manifest: true,
        request_overrides: {
          request_id: 'fb_2',
          resource_id: 'res_drone_fc',
          operation_id: 'unknown_op',
          requested_mode: 'execute',
          params: {},
          grant: {
            grant_id: 'grt_fb_2',
            resource_id: 'res_drone_fc',
            allowed_modes: ['execute'],
            min_grade: 'G1',
            mandate_binding: {
              mandate_id: 'mnd_fb_2',
              fay_id: 'ifay_aaaaaaaabbbbbbbbccccccccdddddddd',
              resource_id: 'res_drone_fc',
              allowed_modes: ['execute'],
              session_grade: 'G1',
              binding_model: 'model_a_plus_b',
              online_fresh: true,
              revoked: false,
              expires_at_epoch_ms: 1800000060000,
              model_a_derived_proof_valid: true,
            },
          },
        },
        expected: {
          decision: 'DENY',
          effective_criticality: 'critical',
          error_code: 'E_UNKNOWN_OPERATION',
          diagnostic_code: 2004,
          escalation_clamped: false,
        },
      },
      {
        id: 'FB_CAP_03_HIGH_CONFIRMED_ALLOW',
        use_reference_manifest: true,
        request_overrides: {
          request_id: 'fb_3',
          resource_id: 'res_drone_fc',
          operation_id: 'unlock_cargo_latch',
          requested_mode: 'execute',
          params: latchParams,
          grant: {
            grant_id: 'grt_fb_3',
            resource_id: 'res_drone_fc',
            allowed_modes: ['execute'],
            min_grade: 'G2',
            mandate_binding: {
              mandate_id: 'mnd_fb_3',
              fay_id: 'ifay_aaaaaaaabbbbbbbbccccccccdddddddd',
              resource_id: 'res_drone_fc',
              allowed_modes: ['execute'],
              session_grade: 'G2',
              binding_model: 'model_a_plus_b',
              online_fresh: true,
              revoked: false,
              expires_at_epoch_ms: 1800000060000,
              model_a_derived_proof_valid: true,
            },
          },
          human_confirmation: {
            confirmation_id: 'cnf_fb_3',
            human_prime_id: 'hid_aaaaaaaabbbbbbbbccccccccdddddddd',
            confirmed_params_sha256: latchHash,
            terminal_attested_disclosure: true,
            expires_at_epoch_ms: 1800000030000,
          },
        },
        expected: {
          decision: 'ALLOW',
          effective_criticality: 'high',
          effective_grade: 'G2',
          escalation_clamped: false,
        },
      },
      {
        id: 'FB_CAP_04_G0_SAFE_STATE',
        use_reference_manifest: true,
        request_overrides: {
          request_id: 'fb_4',
          resource_id: 'res_drone_fc',
          operation_id: 'read_telemetry',
          requested_mode: 'read',
          g0_override: true,
          params: {},
          grant: {
            grant_id: 'grt_fb_4',
            resource_id: 'res_drone_fc',
            allowed_modes: ['read'],
            min_grade: 'G1',
            mandate_binding: {
              mandate_id: 'mnd_fb_4',
              fay_id: 'ifay_aaaaaaaabbbbbbbbccccccccdddddddd',
              resource_id: 'res_drone_fc',
              allowed_modes: ['read'],
              session_grade: 'G1',
              binding_model: 'model_a_plus_b',
              online_fresh: true,
              revoked: false,
              expires_at_epoch_ms: 1800000060000,
              model_a_derived_proof_valid: true,
            },
          },
        },
        expected: {
          decision: 'DENY',
          effective_criticality: 'routine',
          error_code: 'E_G0_EMERGENCY_OVERRIDE',
          diagnostic_code: 2003,
          escalation_clamped: false,
          safe_state_directive: {
            action: 'enter_safe_state',
            safe_state_id: 'hover_and_rtl',
            blocks_human_takeover: false,
          },
        },
      },
    ],
  };
}

function buildFallbackDtpSuite() {
  const sessionKeyHex = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  const ivHex = 'a0a1a2a3a4a5a6a7a8a9aaab';
  const expectedHeader = {
    protocolVersion: { major: 1, minor: 0 },
    frameType: 'data',
    fragmentId: 'frag_0192b4a0-7c10-7000-8000-000000000101',
    agreementId: 'agr_0192b4a0-7c10-7000-8000-000000000001',
    originTimestamp: 1731664800000,
    dagDependencies: [],
    encryptionMetadata: { algorithm: 'AES-256-GCM', keyVersion: 1 },
    sequenceNumber: 1,
  };
  const pt = Buffer.from('{"sensor":"imu","hz":100}', 'utf8');
  const encoded = encodeDtpFrame(
    expectedHeader,
    pt,
    Buffer.from(sessionKeyHex, 'hex'),
    Buffer.from(ivHex, 'hex'),
  );
  const tamperedBuf = Buffer.from(encoded.wireFrame);
  tamperedBuf[tamperedBuf.length - 1] ^= 0x01;

  return {
    wireCryptoPositiveVectors: [
      {
        id: 'fb-dtp-pos-01',
        reencodeExactMatch: true,
        sessionKeyHex,
        ivHex,
        expectedHeader,
        jcsHeader: encoded.jcsHeader,
        plaintextHex: pt.toString('hex'),
        wireFrameHex: encoded.wireFrame.toString('hex'),
      },
    ],
    wireCryptoNegativeVectors: [
      {
        id: 'fb-dtp-neg-01-truncated',
        sessionKeyHex,
        wireFrameHex: '000010',
        expectedErrorCode: 1001,
        expectedErrorName: 'FRAME_DESERIALIZATION_FAILED',
      },
      {
        id: 'fb-dtp-neg-02-tampered-tag',
        sessionKeyHex,
        wireFrameHex: tamperedBuf.toString('hex'),
        expectedErrorCode: 2001,
        expectedErrorName: 'DECRYPTION_FAILED',
      },
    ],
  };
}

function evaluateHierarchyScenario(ctx) {
  const orgParents = new Map();
  const cofayOwners = new Map();
  for (const o of ctx.orgs ?? [ctx.parentOrg, ctx.childOrg].filter(Boolean)) {
    orgParents.set(o, null);
  }
  const linkParent = ({ org, parent, childSigned, parentSigned }) => {
    if (!childSigned || (parent !== null && !parentSigned)) {
      return { ok: false, error: 'HIERARCHY_CONSENT_MISSING' };
    }
    if (parent === org) {
      return { ok: false, error: 'HIERARCHY_CYCLE_CONFLICT' };
    }
    let cur = parent;
    while (cur !== null && cur !== undefined) {
      if (cur === org) return { ok: false, error: 'HIERARCHY_CYCLE_CONFLICT' };
      cur = orgParents.get(cur) ?? null;
    }
    orgParents.set(org, parent);
    return { ok: true };
  };
  const ancestorChain = (org) => {
    const out = [];
    let cur = org;
    while (cur !== null && cur !== undefined) {
      out.push(cur);
      cur = orgParents.get(cur) ?? null;
    }
    return out.reverse();
  };

  if (ctx.action === 'link_hierarchy') {
    for (const link of ctx.links) {
      const r = linkParent(link);
      if (!r.ok) return { outcome: 'rejected', error: r.error };
    }
    return { outcome: 'accepted', ancestorChain: ancestorChain(ctx.queryOrg) };
  }
  if (ctx.action === 'verify_no_rollup') {
    linkParent({
      org: ctx.childOrg,
      parent: ctx.parentOrg,
      childSigned: true,
      parentSigned: true,
    });
    cofayOwners.set(ctx.cofay, ctx.childOrg);
    return {
      outcome: 'accepted',
      cofayOwner: cofayOwners.get(ctx.cofay),
      ancestorChain: ancestorChain(ctx.childOrg),
    };
  }
  return { outcome: 'rejected', error: 'UNKNOWN_SCENARIO' };
}

export function runL2Conformance(options = {}) {
  const checks = [];
  const allowSibling = !options.disableSiblingRepoLookup;

  // 1. CAP 1.0 D-1..D-7 vectors
  const capSiblingPath = join(
    WORKSPACE_SIBLING_ROOT,
    'control-authority-protocol/vectors/semantic/d1-d7-conformance.json',
  );
  const useSiblingCap = allowSibling && existsSync(capSiblingPath);
  const capSuite = useSiblingCap
    ? JSON.parse(readFileSync(capSiblingPath, 'utf8'))
    : buildFallbackCapSuite();

  let capFailures = [];
  for (const vec of capSuite.vectors) {
    const manifest = vec.use_reference_manifest
      ? structuredClone(capSuite.reference_manifest)
      : {
          ...structuredClone(capSuite.reference_manifest),
          signature_ed25519: vec.manifest_tamper_signature,
        };
    const req = {
      protocol_version: '1.0',
      fay_id: 'ifay_aaaaaaaabbbbbbbbccccccccdddddddd',
      now_epoch_ms: 1800000000000,
      manifest,
      ...vec.request_overrides,
    };
    const actual = evaluateCapAction(req, capSuite.trust_anchors);
    const matches =
      actual.decision === vec.expected.decision &&
      actual.effective_criticality === vec.expected.effective_criticality &&
      actual.escalation_clamped === vec.expected.escalation_clamped &&
      (vec.expected.effective_grade === undefined ||
        actual.effective_grade === vec.expected.effective_grade) &&
      (vec.expected.error_code === undefined || actual.error_code === vec.expected.error_code) &&
      (vec.expected.diagnostic_code === undefined ||
        actual.diagnostic_code === vec.expected.diagnostic_code) &&
      (vec.expected.safe_state_directive === undefined ||
        JSON.stringify(actual.safe_state_directive) ===
          JSON.stringify(vec.expected.safe_state_directive));
    if (!matches) {
      capFailures.push(vec.id);
    }
  }
  checks.push({
    id: 'L2-CAP-D1-D7-VECTORS',
    protocol: 'CAP/1.0',
    vectorSource: useSiblingCap ? 'sibling_repo' : 'builtin_fallback',
    vectorCount: capSuite.vectors.length,
    passed: capFailures.length === 0,
    detail:
      capFailures.length === 0
        ? `Verified ${capSuite.vectors.length} CAP 1.0 D-1..D-7 semantic vectors`
        : `Failed CAP vectors: ${capFailures.join(', ')}`,
  });

  // 2. DTP 1.0 wire format JCS + AES-256-GCM vectors
  const dtpSiblingPath = join(
    WORKSPACE_SIBLING_ROOT,
    'data-tunnel-protocol/vectors/dtp-1.0-conformance.json',
  );
  const useSiblingDtp = allowSibling && existsSync(dtpSiblingPath);
  const dtpSuite = useSiblingDtp
    ? JSON.parse(readFileSync(dtpSiblingPath, 'utf8'))
    : buildFallbackDtpSuite();

  let dtpFailures = [];
  for (const pos of dtpSuite.wireCryptoPositiveVectors) {
    const decoded = decodeDtpFrame(
      Buffer.from(pos.wireFrameHex, 'hex'),
      Buffer.from(pos.sessionKeyHex, 'hex'),
    );
    if (
      !decoded.ok ||
      decoded.plaintext.toString('hex') !== pos.plaintextHex ||
      canonicalizeJcs(decoded.header) !== canonicalizeJcs(pos.expectedHeader)
    ) {
      dtpFailures.push(pos.id);
      continue;
    }
    if (pos.reencodeExactMatch) {
      const reencoded = encodeDtpFrame(
        pos.expectedHeader,
        decoded.plaintext,
        Buffer.from(pos.sessionKeyHex, 'hex'),
        Buffer.from(pos.ivHex, 'hex'),
      );
      if (reencoded.wireFrame.toString('hex') !== pos.wireFrameHex) {
        dtpFailures.push(`${pos.id}:reencode`);
      }
    }
  }
  for (const neg of dtpSuite.wireCryptoNegativeVectors) {
    const decoded = decodeDtpFrame(
      Buffer.from(neg.wireFrameHex, 'hex'),
      Buffer.from(neg.sessionKeyHex, 'hex'),
    );
    if (
      decoded.ok ||
      decoded.errorCode !== neg.expectedErrorCode ||
      decoded.errorName !== neg.expectedErrorName
    ) {
      dtpFailures.push(neg.id);
    }
  }
  const dtpCount =
    dtpSuite.wireCryptoPositiveVectors.length + dtpSuite.wireCryptoNegativeVectors.length;
  checks.push({
    id: 'L2-DTP-WIRE-AES-GCM-VECTORS',
    protocol: 'DTP/1.0',
    vectorSource: useSiblingDtp ? 'sibling_repo' : 'builtin_fallback',
    vectorCount: dtpCount,
    passed: dtpFailures.length === 0,
    detail:
      dtpFailures.length === 0
        ? `Verified ${dtpCount} DTP 1.0 JCS + AES-256-GCM wire vectors`
        : `Failed DTP vectors: ${dtpFailures.join(', ')}`,
  });

  // 3. FayID crypto + hierarchy vectors
  const fayidCryptoSiblingPath = join(
    WORKSPACE_SIBLING_ROOT,
    'fayid/vectors/crypto-and-revocation-vectors.json',
  );
  const fayidHierarchyBundlePath = join(
    WORKSPACE_SIBLING_ROOT,
    'fayid/vectors/account-hierarchy-vectors.json',
  );
  const fayidHierarchyDir = join(WORKSPACE_SIBLING_ROOT, 'fayid/vectors/hierarchy');
  const useSiblingFayid = allowSibling && existsSync(fayidCryptoSiblingPath);

  let fayidFailures = [];
  let fayidCount = 0;
  if (useSiblingFayid) {
    const bundle = JSON.parse(readFileSync(fayidCryptoSiblingPath, 'utf8'));
    for (const vec of bundle.subkeyDerivation) {
      fayidCount += 1;
      if (vec.domain === SUBKEY_DOMAINS.EGO_PACKAGE_SIGNING) {
        const key = deriveEgoPackageSigningKey(
          Buffer.from(vec.masterSeedHex, 'hex'),
          vec.signerFayId,
          vec.keyIndex,
        );
        if (
          !key.ok ||
          key.value.publicKeyHex !== vec.expectedPublicKeyHex ||
          !verifyEgoPackageEnvelope(vec.expectedEnvelope, vec.manifest)
        ) {
          fayidFailures.push(vec.id);
        }
      } else {
        const sub = derivePurposeSubkey(
          Buffer.from(vec.masterSeedHex, 'hex'),
          vec.domain,
          vec.context,
        );
        if (!sub.ok || sub.value.publicKeyHex !== vec.expectedPublicKeyHex) {
          fayidFailures.push(vec.id);
        }
      }
    }
    for (const vec of bundle.blindGmcRef) {
      fayidCount += 1;
      const ref = deriveBlindGmcRef(
        vec.humanId,
        Buffer.from(vec.userBlindSaltHex, 'hex'),
        vec.namespace,
      );
      if (!ref.ok || ref.value !== vec.expectedGmcRef) {
        fayidFailures.push(vec.id);
      }
    }
    if (existsSync(fayidHierarchyBundlePath)) {
      const hBundle = JSON.parse(readFileSync(fayidHierarchyBundlePath, 'utf8'));
      for (const item of hBundle.vectors ?? []) {
        fayidCount += 1;
        const actual = evaluateHierarchyScenario(item.context);
        if (canonicalizeJcs(actual) !== canonicalizeJcs(item.expected)) {
          fayidFailures.push(item.id);
        }
      }
    } else if (existsSync(fayidHierarchyDir)) {
      for (const entry of readdirSync(fayidHierarchyDir).sort()) {
        const dirPath = join(fayidHierarchyDir, entry);
        if (!statSync(dirPath).isDirectory()) continue;
        fayidCount += 1;
        const ctx = JSON.parse(readFileSync(join(dirPath, 'context.json'), 'utf8'));
        const expected = JSON.parse(readFileSync(join(dirPath, 'expected.json'), 'utf8'));
        const actual = evaluateHierarchyScenario(ctx);
        if (canonicalizeJcs(actual) !== canonicalizeJcs(expected)) {
          fayidFailures.push(`hierarchy/${entry}`);
        }
      }
    }
  } else {
    // Built-in standalone FayID fallback vectors
    const fallbackScenarios = [
      {
        id: 'fb-fayid-entity',
        ok:
          deriveEntityKeypair(DETERMINISTIC_SEED, 'ifay', 0).value.entityId ===
          'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
      },
      {
        id: 'fb-fayid-hierarchy-two-party',
        ok:
          canonicalizeJcs(
            evaluateHierarchyScenario({
              action: 'link_hierarchy',
              orgs: ['org_parent', 'org_child'],
              links: [
                { org: 'org_child', parent: 'org_parent', childSigned: true, parentSigned: true },
              ],
              queryOrg: 'org_child',
            }),
          ) === canonicalizeJcs({ outcome: 'accepted', ancestorChain: ['org_parent', 'org_child'] }),
      },
      {
        id: 'fb-fayid-hierarchy-cycle-rejected',
        ok:
          evaluateHierarchyScenario({
            action: 'link_hierarchy',
            orgs: ['org_a', 'org_b'],
            links: [
              { org: 'org_b', parent: 'org_a', childSigned: true, parentSigned: true },
              { org: 'org_a', parent: 'org_b', childSigned: true, parentSigned: true },
            ],
            queryOrg: 'org_b',
          }).error === 'HIERARCHY_CYCLE_CONFLICT',
      },
    ];
    fayidCount = fallbackScenarios.length;
    for (const sc of fallbackScenarios) {
      if (!sc.ok) fayidFailures.push(sc.id);
    }
  }

  checks.push({
    id: 'L2-FAYID-CRYPTO-HIERARCHY-VECTORS',
    protocol: 'FayID/1.0',
    vectorSource: useSiblingFayid ? 'sibling_repo' : 'builtin_fallback',
    vectorCount: fayidCount,
    passed: fayidFailures.length === 0,
    detail:
      fayidFailures.length === 0
        ? `Verified ${fayidCount} FayID cryptographic and single-parent hierarchy vectors`
        : `Failed FayID vectors: ${fayidFailures.join(', ')}`,
  });

  // 4. SSP 1.0 built-in positive/negative signed SkillDescriptor vectors
  // (Strictly self-contained; does NOT depend on skill-sharing-protocol/vectors/)
  const sspPublisher = deriveEntityKeypair(DETERMINISTIC_SEED, 'ifay', 2).value;
  const baseSkill = {
    protocol: 'ssp/1.0',
    version: '1.0',
    skillId: 'skill.drone.route_plan',
    name: 'Autonomous Flight Route Planner',
    publisherFayId: sspPublisher.entityId,
    origin: 'https://skills.drone.ifay.example',
    visibility: 'restricted',
    executionMode: 'sync',
    inputSchema: { type: 'object', required: ['waypoints'] },
    outputSchema: { type: 'object', required: ['trajectory'] },
  };
  const signedSkill = signSkillDescriptor(baseSkill, { signer: sspPublisher });
  const sspVectors = [
    {
      id: 'ssp-pos-01-valid-eddsa-jws',
      ok: verifySkillDescriptor(signedSkill, {
        trustedPublicKeyHex: sspPublisher.publicKeyHex,
        consumerVersion: '1.0',
        requireAuthForRestricted: true,
        callerFayId: sspPublisher.entityId,
      }).valid,
    },
    {
      id: 'ssp-pos-02-minor-forward-compat-1.3',
      ok: isSspVersionCompatible('1.3', '1.0'),
    },
    {
      id: 'ssp-neg-01-payload-tampered',
      ok: !verifySkillDescriptor(
        { ...signedSkill, visibility: 'public' },
        { trustedPublicKeyHex: sspPublisher.publicKeyHex },
      ).valid,
    },
    {
      id: 'ssp-neg-02-major-2.0-incompatible',
      ok: !verifySkillDescriptor(
        { ...signedSkill, version: '2.0' },
        { trustedPublicKeyHex: sspPublisher.publicKeyHex, consumerVersion: '1.0' },
      ).valid,
    },
    {
      id: 'ssp-neg-03-restricted-unauthenticated-rejected',
      ok:
        verifySkillDescriptor(signedSkill, {
          trustedPublicKeyHex: sspPublisher.publicKeyHex,
          requireAuthForRestricted: true,
        }).errorCode === 'SSP_VISIBILITY_AUTH_REQUIRED',
    },
  ];
  const sspFailed = sspVectors.filter((v) => !v.ok).map((v) => v.id);
  checks.push({
    id: 'L2-SSP-SIGNED-DESCRIPTOR-VECTORS',
    protocol: 'SSP/1.0',
    vectorSource: 'builtin_fallback',
    vectorCount: sspVectors.length,
    passed: sspFailed.length === 0,
    detail:
      sspFailed.length === 0
        ? `Verified ${sspVectors.length} SSP 1.0 JCS + Detached Ed25519 JWS vectors`
        : `Failed SSP vectors: ${sspFailed.join(', ')}`,
  });

  if (options.injectL2FailureForTest) {
    checks.push({
      id: 'L2-INJECTED-FAILURE',
      protocol: 'TEST',
      vectorSource: 'builtin_fallback',
      vectorCount: 1,
      passed: false,
      detail: 'Synthetic L2 failure injected to verify progressive L3 gate blocking',
    });
  }

  const passedCount = checks.filter((c) => c.passed).length;
  const failedCount = checks.length - passedCount;
  return {
    level: 'L2',
    status: failedCount === 0 ? 'passed' : 'failed',
    passedCount,
    failedCount,
    checks,
  };
}

// ============================================================================
// L3: End-to-End Phase 1/2 Lifecycle Integration & Hash-Chained Audit Trail
// ============================================================================

export function runL3Conformance() {
  const checks = [];
  const audit = createAuditHashChain();

  // Step 1: Human Prime -> iFay FayID derivation
  const humanPrime = deriveEntityKeypair(DETERMINISTIC_SEED, 'hid', 0).value;
  const clientIfay = deriveEntityKeypair(DETERMINISTIC_SEED, 'ifay', 0).value;
  const step1Ok =
    isValidFayId(humanPrime.entityId, 'HUMAN_ID') && isValidFayId(clientIfay.entityId, 'IFAY_ID');
  audit.append('IDENTITY_PROVISIONED', {
    humanPrimeId: humanPrime.entityId,
    fayId: clientIfay.entityId,
  });
  checks.push({
    id: 'L3-STEP-01-IDENTITY',
    passed: step1Ok,
    detail: 'Human Prime and iFay Ed25519 identities derived via FayID HKDF-SHA256',
  });

  // Step 2: Faying 1.0 Mandate issuance & verification
  const mandate = createFayingMandate(
    {
      mandateId: 'mnd_e2e_phase2_01',
      humanPrimeId: humanPrime.entityId,
      fayId: clientIfay.entityId,
      grade: 'G2',
      bindingModel: 'model_a_plus_b',
      scope: {
        resources: ['res_host_drone_fc'],
        actions: ['read', 'execute'],
        domains: ['https://skills.ifay.example/v1'],
        terminals: ['terminal:host-station:01'],
      },
      deviceId: 'terminal:host-station:01',
      issuedAtEpochMs: 1800000000000,
      expiresAtEpochMs: 1800003600000,
    },
    humanPrime,
  );
  const mandateVerification = verifyFayingMandate(mandate, {
    trustedIssuerPublicKeyHex: humanPrime.publicKeyHex,
    nowEpochMs: 1800000010000,
    requiredResource: 'res_host_drone_fc',
    requiredAction: 'execute',
  });
  audit.append('FAYING_MANDATE_VERIFIED', {
    mandateId: mandate.mandateId,
    grade: mandate.grade,
    valid: mandateVerification.valid,
  });
  checks.push({
    id: 'L3-STEP-02-FAYING-MANDATE',
    passed: mandateVerification.valid,
    detail: 'Faying 1.0 G2 Mandate signed by Human Prime and verified on Host',
  });

  // Step 3: Declarative FayManifest assembly & Phase 2 resolution
  const manifest = createFayManifest({
    name: 'e2e-live-ifay',
    version: '1.0.0',
    description: 'End-to-end iFACTS L3 integration target',
    vendor: 'iFay Conformance Suite',
    fayId: clientIfay.entityId,
    controlMode: 'ego',
    modules: [
      { id: 'device_driver_hub', version: '^1.0.0' },
      { id: 'sensor', version: '^1.0.0' },
      { id: 'personal_data_heap', version: '^1.0.0' },
    ],
    protocols: [
      { id: 'cap_protocol', version: '^1.0.0' },
      { id: 'dtp_protocol', version: '^1.0.0' },
    ],
    drivers: [
      {
        name: 'Host Drone Flight Controller',
        type: 'device',
        driverPackage: '@drone-drivers/dji-fc',
      },
    ],
    ego: {
      modelSource: '@ego-models/pilot-assistant-v1',
      constraints: {
        skillBoundaries: {
          allowed: ['flight', 'telemetry'],
          restricted: ['financial'],
        },
      },
    },
  });
  const deps = resolveFayManifestDependencies(manifest);
  const phaseInfo = classifyFayManifestPhase(manifest);
  const step3Ok =
    phaseInfo.phase === 'Phase 2' &&
    deps.modules.includes('ego_model') &&
    deps.protocols.includes('faying_protocol');
  audit.append('FAYMANIFEST_ASSEMBLED', {
    name: manifest.name,
    resolvedPhase: phaseInfo.phase,
    moduleCount: deps.modules.length,
  });
  checks.push({
    id: 'L3-STEP-03-FAYMANIFEST-ASSEMBLY',
    passed: step3Ok,
    detail: `Assembled ${manifest.name} (${phaseInfo.phase}) with ${deps.modules.length} resolved modules`,
  });

  // Step 4: CAP 1.0 D-1..D-7 command gate (ALLOW + unknown DENY + G0 safe-state)
  const capAnchorSeed = Buffer.alloc(32, 0x42);
  const capAnchorKp = ed25519KeypairFromSeed(capAnchorSeed);
  const trustAnchors = {
    key_e2e_anchor: { algorithm: 'Ed25519', public_key_raw_hex: capAnchorKp.publicKeyHex },
  };
  const capDriverManifest = signCapDriverManifest(
    {
      manifest_id: 'mf_e2e_01',
      driver_id: 'drv_e2e_fc',
      version: '1.0.0',
      issued_at: '2026-11-16T00:00:00Z',
      signer_key_id: 'key_e2e_anchor',
      resources: [
        {
          resource_id: 'res_host_drone_fc',
          safe_states: [{ safe_state_id: 'hover_and_rtl', description: 'Hover and return' }],
          operations: [
            {
              operation_id: 'takeoff_waypoint',
              mode: 'execute',
              criticality: 'high',
              consequence_irreversibility: 'irreversible_consequence',
              domain_category: 'device_control',
            },
          ],
        },
      ],
    },
    capAnchorSeed,
  );
  const cmdParams = { altitudeMeters: 30, waypointId: 'WP-01' };
  const capAllow = evaluateCapAction(
    {
      protocol_version: '1.0',
      request_id: 'req_e2e_allow',
      fay_id: clientIfay.entityId,
      now_epoch_ms: 1800000020000,
      resource_id: 'res_host_drone_fc',
      operation_id: 'takeoff_waypoint',
      requested_mode: 'execute',
      params: cmdParams,
      manifest: capDriverManifest,
      grant: {
        grant_id: 'grt_e2e_01',
        resource_id: 'res_host_drone_fc',
        allowed_modes: ['execute'],
        min_grade: 'G2',
        mandate_binding: toCapMandateBinding(mandate, 'res_host_drone_fc'),
      },
      human_confirmation: {
        confirmation_id: 'cnf_e2e_01',
        human_prime_id: humanPrime.entityId,
        confirmed_params_sha256: computeCapParamsSha256(cmdParams),
        terminal_attested_disclosure: true,
        expires_at_epoch_ms: 1800000050000,
      },
    },
    trustAnchors,
  );
  const g0Mandate = triggerG0EmergencyTakeover(mandate, humanPrime, 1800000030000);
  const capG0 = evaluateCapAction(
    {
      protocol_version: '1.0',
      request_id: 'req_e2e_g0',
      fay_id: clientIfay.entityId,
      now_epoch_ms: 1800000031000,
      resource_id: 'res_host_drone_fc',
      operation_id: 'takeoff_waypoint',
      requested_mode: 'execute',
      params: cmdParams,
      manifest: capDriverManifest,
      grant: {
        grant_id: 'grt_e2e_01',
        resource_id: 'res_host_drone_fc',
        allowed_modes: ['execute'],
        min_grade: 'G2',
        mandate_binding: toCapMandateBinding(g0Mandate, 'res_host_drone_fc'),
      },
    },
    trustAnchors,
  );
  const step4Ok =
    capAllow.decision === 'ALLOW' &&
    capG0.decision === 'DENY' &&
    capG0.safe_state_directive?.safe_state_id === 'hover_and_rtl';
  audit.append('CAP_COMMAND_GATED', {
    allowDecision: capAllow.decision,
    g0SafeState: capG0.safe_state_directive?.safe_state_id,
  });
  checks.push({
    id: 'L3-STEP-04-CAP-SAFETY-GATE',
    passed: step4Ok,
    detail: 'CAP D-1..D-7 high-criticality execution and G0 emergency safe-state verified',
  });

  // Step 5: DTP 1.0 AES-256-GCM encrypted telemetry frame round-trip
  const dtpSessionKey = Buffer.alloc(32, 0x5a);
  const dtpIv = Buffer.alloc(12, 0x2b);
  const telemetryJson = canonicalizeJcs({
    altitudeMeters: 30,
    batteryPct: 94,
    hostStatus: 'nominal',
  });
  const dtpHeader = {
    protocolVersion: { major: 1, minor: 0 },
    frameType: 'data',
    fragmentId: 'frag_e2e_telemetry_01',
    agreementId: 'agr_e2e_heap_01',
    originTimestamp: 1800000025000,
    dagDependencies: [],
    encryptionMetadata: { algorithm: 'AES-256-GCM', keyVersion: 1 },
    sequenceNumber: 1,
  };
  const sealed = encodeDtpFrame(
    dtpHeader,
    Buffer.from(telemetryJson, 'utf8'),
    dtpSessionKey,
    dtpIv,
  );
  const opened = decodeDtpFrame(sealed.wireFrame, dtpSessionKey);
  const step5Ok = opened.ok && opened.plaintext.toString('utf8') === telemetryJson;
  audit.append('DTP_TELEMETRY_TUNNELED', {
    fragmentId: dtpHeader.fragmentId,
    wireBytes: sealed.wireFrame.length,
  });
  checks.push({
    id: 'L3-STEP-05-DTP-ENCRYPTED-TUNNEL',
    passed: step5Ok,
    detail: 'DTP 1.0 JCS header + AES-256-GCM encrypted telemetry frame verified end-to-end',
  });

  // Step 6: Signed Ego Vault package mount verification
  const signedEgo = signEgoVaultManifest(
    {
      version: '1.0.0',
      created_at: '2026-11-16T00:00:00Z',
      base_model: 'qwen3.5-0.8B',
      editions: ['normal'],
      training_backend: 'mlx',
      fidelity_report: {
        schema_version: '1.0',
        status: 'measured',
        holdout_sample_count: 32,
        holdout_loss: 1.04,
        holdout_perplexity: 2.83,
        cell_consistency_score: 0.95,
        probe_win_rate: 0.91,
        drift_from_baseline: 0.04,
      },
      integrity: {
        schema_version: '1.0',
        base_model_digest: 'unverified_offline',
        cell_digests: {
          'normal/adapters/ego-lora.safetensors':
            'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
      },
    },
    { masterSeed: DETERMINISTIC_SEED, signerFayId: clientIfay.entityId },
  );
  const egoVerify = verifyEgoVaultManifest(signedEgo, {
    trustedPublicKeyHex: signedEgo.signature.public_key_hex,
  });
  audit.append('EGO_PACKAGE_MOUNTED', {
    signerFayId: signedEgo.signature.signer_fay_id,
    payloadJcsSha256: signedEgo.signature.payload_jcs_sha256,
  });
  checks.push({
    id: 'L3-STEP-06-EGO-SIGNED-MOUNT',
    passed: egoVerify.valid,
    detail: 'Two-tier signed Ego Vault manifest verified and mounted cleanly',
  });

  // Step 7: SHA-256 hash-chained audit trail verification
  const auditEntries = audit.entries();
  const chainVer = verifyAuditHashChain(auditEntries);
  checks.push({
    id: 'L3-STEP-07-HASH-CHAIN-AUDIT',
    passed: chainVer.valid,
    detail: chainVer.valid
      ? `SHA-256 hash-chained audit trail verified (${chainVer.length} linked events, head=${chainVer.headHash.slice(0, 16)}...)`
      : `Audit chain broken at index ${chainVer.brokenIndex}`,
  });

  const passedCount = checks.filter((c) => c.passed).length;
  const failedCount = checks.length - passedCount;
  return {
    level: 'L3',
    status: failedCount === 0 ? 'passed' : 'failed',
    passedCount,
    failedCount,
    checks,
    auditTrail: auditEntries,
  };
}

// ============================================================================
// iFay Ready Application Certification Tier Evaluator
// ============================================================================

export function evaluateIfayReadyTier(capabilities = {}, levelStatuses = {}) {
  const hasBronzeCaps = Boolean(
    capabilities.firstPersonTracer && capabilities.simulatedOperation,
  );
  const hasSilverCaps = Boolean(
    capabilities.capProtocol && capabilities.dtpProtocol && capabilities.credentialDelegation,
  );
  const hasGoldCaps = Boolean(
    hasSilverCaps && capabilities.sspProtocol && capabilities.cfsIntegration,
  );

  const l1Passed = levelStatuses.L1 === 'passed';
  const l2Passed = l1Passed && levelStatuses.L2 === 'passed';
  const l3Passed = l2Passed && levelStatuses.L3 === 'passed';

  const eligibleTiers = [];
  if (hasBronzeCaps && l1Passed) {
    eligibleTiers.push('Bronze');
  }
  if (hasSilverCaps && l2Passed) {
    eligibleTiers.push('Silver');
  }
  if (hasGoldCaps && l3Passed) {
    eligibleTiers.push('Gold');
  }

  let tier = 'None';
  let rationale = 'Application does not yet meet Bronze UI operability or L1 baseline requirements.';
  if (eligibleTiers.includes('Gold')) {
    tier = 'Gold';
    rationale =
      'Supports SSP skill sharing + full C/F/S integration and passed iFACTS L1, L2, and L3.';
  } else if (eligibleTiers.includes('Silver')) {
    tier = 'Silver';
    rationale =
      'Supports CAP direct control + DTP data exchange + credential delegation and passed iFACTS L1 + L2.';
  } else if (eligibleTiers.includes('Bronze')) {
    tier = 'Bronze';
    rationale =
      'Supports First-person Tracer + Simulated Operation UI operability with L1 baseline passed.';
  }

  return {
    tier,
    eligibleTiers,
    rationale,
  };
}

// ============================================================================
// Top-Level Progressive Suite Runner -> ifacts-report/1.0
// ============================================================================

export function runIfactsSuite(options = {}) {
  const candidateSubjectId = options.subjectId ?? options.manifest?.fayId ?? null;
  const generatedAt = options.generatedAt ?? '2026-11-16T00:00:00Z';

  // Enforce strict coFay -> coFACTS boundary BEFORE executing L1..L3
  if (
    options.entityType === 'cofay' ||
    (typeof candidateSubjectId === 'string' &&
      candidateSubjectId.toLowerCase().startsWith('cofay_'))
  ) {
    return {
      reportFormat: IFACTS_REPORT_FORMAT,
      generatedAt,
      subject: candidateSubjectId ?? 'cofay_unspecified',
      overallStatus: 'rejected_out_of_scope',
      errorCode: COFAY_BOUNDARY_ERROR_CODE,
      message:
        'coFay (Common Fay) conformance is outside iFACTS scope; run coFACTS instead.',
      resolvedPhase: null,
      levels: {
        L1: { level: 'L1', status: 'not_applicable_cofay', passedCount: 0, failedCount: 0, checks: [] },
        L2: { level: 'L2', status: 'not_applicable_cofay', passedCount: 0, failedCount: 0, checks: [] },
        L3: { level: 'L3', status: 'not_applicable_cofay', passedCount: 0, failedCount: 0, checks: [] },
        L4: { level: 'L4', status: 'not_applicable_cofay', note: 'Use coFACTS for coFay targets.' },
      },
      ifayReady: {
        tier: 'None',
        eligibleTiers: [],
        rationale: 'coFay targets are evaluated by coFACTS, not iFACTS.',
      },
    };
  }

  const l1 = runL1Conformance(options);
  let l2;
  let l3;

  if (l1.status !== 'passed') {
    l2 = {
      level: 'L2',
      status: 'blocked_by_previous_level',
      passedCount: 0,
      failedCount: 0,
      checks: [],
    };
    l3 = {
      level: 'L3',
      status: 'blocked_by_previous_level',
      passedCount: 0,
      failedCount: 0,
      checks: [],
    };
  } else {
    options.hooks?.onL2Start?.();
    l2 = runL2Conformance(options);
    if (l2.status !== 'passed') {
      l3 = {
        level: 'L3',
        status: 'blocked_by_previous_level',
        passedCount: 0,
        failedCount: 0,
        checks: [],
      };
    } else {
      options.hooks?.onL3Start?.();
      l3 = runL3Conformance(options);
    }
  }

  const l4 = {
    level: 'L4',
    status: 'deferred_phase_4_behavioral',
    note: 'System-level long-horizon ethics priority, multi-terminal drift, and Ego version-switch audits require live multi-Host behavioral evaluation.',
  };

  const defaultCaps = options.appCapabilities ?? {
    firstPersonTracer: true,
    simulatedOperation: true,
    capProtocol: true,
    dtpProtocol: true,
    credentialDelegation: true,
    sspProtocol: true,
    cfsIntegration: true,
  };

  const ifayReady = evaluateIfayReadyTier(defaultCaps, {
    L1: l1.status,
    L2: l2.status,
    L3: l3.status,
  });

  const resolvedPhase =
    options.manifest && l1.status === 'passed'
      ? classifyFayManifestPhase(options.manifest).phase
      : 'Phase 2';

  const overallStatus =
    l1.status === 'passed' && l2.status === 'passed' && l3.status === 'passed'
      ? 'passed'
      : 'failed';

  return {
    reportFormat: IFACTS_REPORT_FORMAT,
    generatedAt,
    subject:
      candidateSubjectId ??
      'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
    overallStatus,
    resolvedPhase,
    levels: {
      L1: l1,
      L2: l2,
      L3: {
        level: l3.level,
        status: l3.status,
        passedCount: l3.passedCount,
        failedCount: l3.failedCount,
        checks: l3.checks,
      },
      L4: l4,
    },
    ifayReady,
    summary: {
      totalChecksExecuted:
        l1.checks.length + l2.checks.length + (l3.checks?.length ?? 0),
      totalPassed: l1.passedCount + l2.passedCount + (l3.passedCount ?? 0),
      totalFailed: l1.failedCount + l2.failedCount + (l3.failedCount ?? 0),
    },
  };
}
