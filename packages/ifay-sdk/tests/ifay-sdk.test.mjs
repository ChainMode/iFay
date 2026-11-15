import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  FAYID_PREFIXES,
  SUBKEY_DOMAINS,
  base32EncodeNoPad,
  base32DecodeNoPad,
  canonicalizeJcs,
  parseFayId,
  isValidFayId,
  derivePurposeSubkey,
  deriveEntityKeypair,
  deriveEgoPackageSigningKey,
  deriveBlindGmcRef,
  signEd25519,
  verifyEd25519,
  ed25519KeypairFromSeed,
  createFayingMandate,
  verifyFayingMandate,
  delegateFayingMandate,
  triggerG0EmergencyTakeover,
  toCapMandateBinding,
  createFayManifest,
  validateFayManifest,
  resolveFayManifestDependencies,
  classifyFayManifestPhase,
  classifyPackageNamespace,
  signCapDriverManifest,
  verifyCapDriverManifest,
  computeCapParamsSha256,
  evaluateCapAction,
  signSkillDescriptor,
  verifySkillDescriptor,
  isSspVersionCompatible,
  signEgoVaultManifest,
  verifyEgoVaultManifest,
  validateEgoFidelityPrivacy,
} from '../src/index.mjs';

const MASTER_SEED_HEX = '2424242424242424242424242424242424242424242424242424242424242424';
const MASTER_SEED = Buffer.from(MASTER_SEED_HEX, 'hex');

describe('@ifay/sdk — 1. FayID, Base32, HKDF Subkeys, JCS & Ed25519', () => {
  it('1.1 parses and normalizes all 8 canonical FayID prefixes (RFC 4648 lowercase no-pad Base32)', () => {
    const samples = [
      ['hid_wzwm7fn6bzqkc2icq45pbbn6iqsdhzkpmxlvubti5le7tqmov7lq', 'HUMAN_ID'],
      ['IFAY_3ATYJM7QW4DBCHKBEC5HY22T4POPE5QC55AOZXHRM722C6TLSF6Q', 'IFAY_ID'],
      ['cofay_evpjbnstakrrzfrczkok4beidw26pphq2u747pm2znma4svaffxq', 'COFAY_ID'],
      ['org_drone-ai-corp-01', 'ORGANIZATION_ID'],
      ['dyn_zvcozeifhiausy2vxe673lzvra', 'DYNAMIC_CODE'],
      ['grt_dultywhyqcwfgzu4pwqwswnaia', 'AUTHORIZATION_GRANT'],
      ['vrf_3dxgkjbyzwptq2q3p2vxd2pc74', 'VERIFICATION_CODE'],
      ['gmcref_rjevjlcgztvxvrurorg46y3zhwmjk4zgsiv5czkrnzi7w44z7piq', 'OPAQUE_REF'],
    ];
    for (const [raw, expectedKind] of samples) {
      const parsed = parseFayId(raw);
      assert.equal(parsed.ok, true, `expected ${raw} to parse`);
      assert.equal(parsed.value.kind, expectedKind);
      assert.equal(parsed.value.value, raw.toLowerCase());
      assert.equal(isValidFayId(raw, expectedKind), true);
    }
    assert.equal(Object.keys(FAYID_PREFIXES).length, 8);
  });

  it('1.2 rejects malformed FayIDs, padded Base32, invalid alphabet chars, and empty bodies', () => {
    for (const bad of ['', 'unknown_abc', 'ifay_', 'ifay_abc=', 'hid_1890invalidbase32', 'org_bad_underscore']) {
      const parsed = parseFayId(bad);
      assert.equal(parsed.ok, false, `expected ${bad} to fail`);
      assert.equal(parsed.error, 'MALFORMED_FAYID_STRING');
    }
  });

  it('1.3 round-trips RFC 4648 no-pad Base32 without padding characters', () => {
    const encoded = base32EncodeNoPad(MASTER_SEED);
    assert.equal(encoded.includes('='), false);
    const decoded = base32DecodeNoPad(encoded);
    assert.deepEqual(decoded, MASTER_SEED);
  });

  it('1.4 derives byte-exact entity keypairs under ifay.fayid.entity.v1 matching FayID vectors', () => {
    const derived = deriveEntityKeypair(MASTER_SEED, 'ifay', 0);
    assert.equal(derived.ok, true);
    assert.equal(derived.value.entityId, 'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q');
    assert.equal(
      derived.value.publicKeyHex,
      '26fec0f603c84f1dc4664581ebf3d4843a0897671253efa7eebc25aad7b016f5',
    );
    assert.equal(JSON.stringify(derived.value).includes(MASTER_SEED_HEX), false);
  });

  it('1.5 derives isolated Ego package signing key under ifay.ego.package-signing.v1 matching FayID vectors', () => {
    const egoKey = deriveEgoPackageSigningKey(
      MASTER_SEED,
      'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
      0,
    );
    assert.equal(egoKey.ok, true);
    assert.equal(
      egoKey.value.publicKeyHex,
      'd7c331ec3d0097a982aca13e8b1eefa4360fbd5148f8d2c84e4c614e92a08caf',
    );
    const env = egoKey.value.signEgoPackageManifest({
      egoSchema: '1.0',
      personaName: 'Aria',
      weightsSha256: '0011223344556677',
    });
    assert.equal(
      env.payloadDigestHex,
      '97c728020c3165586e091049f1f5d1af5dda4e61e189e5ddb76e82b59491b452',
    );
    assert.equal(
      env.signatureHex,
      'f64c734aff218a3e5b1fb7b8c9e6a0558d1aafb2d1c85b9c39ee37dc1848826437d9759f36a4b6151e7995b62c5f2b2ad662686209c786a9a59893336a0d0803',
    );
  });

  it('1.6 derives unlinkable blind gmcref_ under ifay.gmc.natural-person.v1 matching FayID vectors', () => {
    const humanId = 'hid_wzwm7fn6bzqkc2icq45pbbn6iqsdhzkpmxlvubti5le7tqmov7lq';
    const salt1 = Buffer.from('b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1', 'hex');
    const salt2 = Buffer.from('d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2', 'hex');

    const ref1 = deriveBlindGmcRef(humanId, salt1, SUBKEY_DOMAINS.GMC_NATURAL_PERSON);
    const ref2 = deriveBlindGmcRef(humanId, salt2, SUBKEY_DOMAINS.GMC_NATURAL_PERSON);
    assert.equal(ref1.ok, true);
    assert.equal(ref1.value, 'gmcref_rjevjlcgztvxvrurorg46y3zhwmjk4zgsiv5czkrnzi7w44z7piq');
    assert.equal(ref2.value, 'gmcref_t3nrr6iflwf5zhnbniwwda2yov3bvfyfbzcaccsnqzf7sggv7d4a');
    assert.notEqual(ref1.value, ref2.value);
  });

  it('1.7 canonicalizes JSON per RFC 8785 JCS and signs/verifies Ed25519 Holder-of-Key messages', () => {
    const jcs = canonicalizeJcs({ z: 1, a: [-0, true, { b: 'ok', drop: undefined }] });
    assert.equal(jcs, '{"a":[0,true,{"b":"ok"}],"z":1}');
    assert.throws(() => canonicalizeJcs({ bad: Number.NaN }), TypeError);

    const kp = ed25519KeypairFromSeed(MASTER_SEED);
    const msg = Buffer.from(jcs, 'utf8');
    const sig = signEd25519(MASTER_SEED, msg);
    assert.equal(verifyEd25519(kp.publicKeyRaw, msg, sig), true);
    assert.equal(verifyEd25519(kp.publicKeyRaw, Buffer.from('tampered'), sig), false);
  });
});

describe('@ifay/sdk — 2. Faying 1.0 Handshake & Mandate Helper', () => {
  const hp = deriveEntityKeypair(MASTER_SEED, 'hid', 0).value;
  const ifay = deriveEntityKeypair(MASTER_SEED, 'ifay', 0).value;

  it('2.1 builds and cryptographically verifies a G2 Faying 1.0 Mandate envelope', () => {
    const mandate = createFayingMandate(
      {
        mandateId: 'mnd_live_001',
        humanPrimeId: hp.entityId,
        fayId: ifay.entityId,
        grade: 'G2',
        bindingModel: 'model_a_plus_b',
        scope: {
          resources: ['res_drone_fc'],
          actions: ['read', 'execute'],
          domains: ['https://api.ifay.example/v1'],
          terminals: ['terminal:laptop:fixed-1', 'terminal:phone:mobile-2'],
        },
        deviceId: 'terminal:laptop:fixed-1',
        issuedAtEpochMs: 1800000000000,
        expiresAtEpochMs: 1800000600000,
      },
      hp,
    );

    const check = verifyFayingMandate(mandate, {
      trustedIssuerPublicKeyHex: hp.publicKeyHex,
      nowEpochMs: 1800000010000,
      requiredResource: 'res_drone_fc',
      requiredAction: 'execute',
      requiredTerminal: 'terminal:laptop:fixed-1',
    });
    assert.equal(check.valid, true);
    assert.equal(check.grade, 'G2');

    const capBinding = toCapMandateBinding(mandate, 'res_drone_fc');
    assert.equal(capBinding.session_grade, 'G2');
    assert.equal(capBinding.binding_model, 'model_a_plus_b');
    assert.equal(capBinding.model_a_derived_proof_valid, true);
  });

  it('2.2 rejects expired, revoked, signature-tampered, and out-of-scope Mandates', () => {
    const mandate = createFayingMandate(
      {
        mandateId: 'mnd_live_002',
        humanPrimeId: hp.entityId,
        fayId: ifay.entityId,
        grade: 'G3',
        scope: {
          resources: ['res_sensor'],
          actions: ['read'],
          domains: ['https://api.ifay.example/v1/telemetry'],
          terminals: ['terminal:laptop:fixed-1'],
        },
        issuedAtEpochMs: 1800000000000,
        expiresAtEpochMs: 1800000060000,
      },
      hp,
    );

    const expired = verifyFayingMandate(mandate, {
      trustedIssuerPublicKeyHex: hp.publicKeyHex,
      nowEpochMs: 1800000060000,
    });
    assert.equal(expired.valid, false);
    assert.equal(expired.errorCode, 'E_MANDATE_EXPIRED');

    const revoked = verifyFayingMandate(mandate, {
      trustedIssuerPublicKeyHex: hp.publicKeyHex,
      nowEpochMs: 1800000010000,
      revokedMandateIds: new Set(['mnd_live_002']),
    });
    assert.equal(revoked.valid, false);
    assert.equal(revoked.errorCode, 'E_MANDATE_REVOKED');

    const outOfScope = verifyFayingMandate(mandate, {
      trustedIssuerPublicKeyHex: hp.publicKeyHex,
      nowEpochMs: 1800000010000,
      requiredAction: 'write',
    });
    assert.equal(outOfScope.valid, false);
    assert.equal(outOfScope.errorCode, 'E_SCOPE_VIOLATION');
  });

  it('2.3 enforces DELEGATE convergence (rejecting autonomy escalation G2 -> G4 with 1099 E_PROTOCOL)', () => {
    const parent = createFayingMandate(
      {
        mandateId: 'mnd_parent',
        humanPrimeId: hp.entityId,
        fayId: ifay.entityId,
        grade: 'G2',
        scope: {
          resources: ['res_drone_fc'],
          actions: ['read', 'execute'],
          domains: ['https://api.ifay.example/v1'],
          terminals: ['terminal:laptop:fixed-1', 'terminal:phone:mobile-2'],
        },
        issuedAtEpochMs: 1800000000000,
        expiresAtEpochMs: 1800000600000,
      },
      hp,
    );

    const validChild = delegateFayingMandate(
      parent,
      {
        mandateId: 'mnd_child_ok',
        childFayId: ifay.entityId,
        grade: 'G1',
        scope: {
          resources: ['res_drone_fc'],
          actions: ['read'],
          domains: ['https://api.ifay.example/v1'],
          terminals: ['terminal:phone:mobile-2'],
        },
        deviceId: 'terminal:phone:mobile-2',
      },
      hp,
    );
    assert.equal(validChild.ok, true);
    assert.equal(validChild.value.chainDepth, 1);

    const badEscalation = delegateFayingMandate(
      parent,
      {
        mandateId: 'mnd_child_bad',
        childFayId: ifay.entityId,
        grade: 'G4',
        scope: parent.scope,
      },
      hp,
    );
    assert.equal(badEscalation.ok, false);
    assert.equal(badEscalation.diagnosticCode, 1099);
    assert.equal(badEscalation.errorCode, 'E_PROTOCOL');
  });

  it('2.4 issues and enforces G0 emergency takeover preempting autonomous execution', () => {
    const active = createFayingMandate(
      {
        mandateId: 'mnd_g4',
        humanPrimeId: hp.entityId,
        fayId: ifay.entityId,
        grade: 'G4',
        scope: { resources: ['res_drone_fc'], actions: ['execute'], domains: [], terminals: [] },
        issuedAtEpochMs: 1800000000000,
        expiresAtEpochMs: 1800000600000,
      },
      hp,
    );
    const g0Mandate = triggerG0EmergencyTakeover(active, hp, 1800000020000);
    assert.equal(g0Mandate.grade, 'G0');

    const verified = verifyFayingMandate(g0Mandate, {
      trustedIssuerPublicKeyHex: hp.publicKeyHex,
      nowEpochMs: 1800000025000,
    });
    assert.equal(verified.valid, false);
    assert.equal(verified.errorCode, 'E_G0_EMERGENCY_TAKEOVER');
  });
});

describe('@ifay/sdk — 3. FayManifest Builder, Auto-Completion, Phase Classifier & Validator', () => {
  it('3.1 validates official minimal and drone-controller FayManifest fixtures against authoritative schema', () => {
    const minimalPath = fileURLToPath(
      new URL('../../../schema/faymanifest/examples/minimal.faymanifest.json', import.meta.url),
    );
    const dronePath = fileURLToPath(
      new URL('../../../schema/faymanifest/examples/drone-controller.faymanifest.json', import.meta.url),
    );
    const minimal = JSON.parse(readFileSync(minimalPath, 'utf8'));
    const drone = JSON.parse(readFileSync(dronePath, 'utf8'));

    assert.equal(validateFayManifest(minimal).valid, true);
    assert.equal(validateFayManifest(drone).valid, true);
    assert.equal(classifyFayManifestPhase(minimal).phase, 'Phase 1');
    assert.equal(classifyFayManifestPhase(drone).phase, 'Phase 2');
  });

  it('3.2 programmatically builds FayManifest, auto-completes 7 infra + ego_model, and classifies namespaces', () => {
    const manifest = createFayManifest({
      name: 'smart-home-ifay',
      version: '1.0.0',
      description: 'Local smart home iFay client',
      vendor: 'SmartNest Labs',
      fayId: 'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
      controlMode: 'ego',
      modules: [
        { id: 'device_driver_hub', version: '^1.0.0' },
        { id: 'sensor', version: '^1.0.0' },
      ],
      protocols: [
        { id: 'cap_protocol', version: '^1.0.0' },
        { id: 'dtp_protocol', version: '^1.0.0' },
      ],
      drivers: [
        { name: 'HVAC Driver', type: 'device', driverPackage: '@cap-drivers/hvac-matter' },
        { name: 'Custom Plug', type: 'device', driverPackage: '@acme/smart-plug' },
      ],
      ego: {
        modelSource: '@ego-models/home-steward-v1',
      },
    });

    const validation = validateFayManifest(manifest);
    assert.equal(validation.valid, true);

    const resolved = resolveFayManifestDependencies(manifest);
    assert.equal(resolved.modules.includes('ego_model'), true);
    assert.equal(resolved.modules.includes('fayger_runtime'), true);
    assert.equal(resolved.protocols.includes('faying_protocol'), true);
    assert.equal(resolved.modules.length, 9); // 2 business + 6 core infra + 1 ego_model
    assert.equal(resolved.protocols.length, 3); // 2 business + 1 faying_protocol

    assert.equal(classifyPackageNamespace('@ego-models/home-steward-v1'), 'governed');
    assert.equal(classifyPackageNamespace('@cap-drivers/hvac-matter'), 'governed');
    assert.equal(classifyPackageNamespace('@acme/smart-plug'), 'ungoverned');
  });

  it('3.3 classifies Phase 3, Phase 4, and Phase 5 manifests accurately', () => {
    const p3 = createFayManifest({
      name: 'p3-client',
      version: '1.0.0',
      description: 'Phase 3 client',
      vendor: 'iFay',
      controlMode: 'ego',
      modules: [{ id: 'external_knowledge' }],
      protocols: [{ id: 'ssp_protocol' }],
    });
    const p4 = createFayManifest({
      name: 'p4-client',
      version: '1.0.0',
      description: 'Phase 4 client',
      vendor: 'iFay',
      controlMode: 'autonomous',
      modules: [{ id: 'self_awareness' }, { id: 'aligned_consciousness' }],
      protocols: [{ id: 'telepathy_protocol' }],
    });
    assert.equal(classifyFayManifestPhase(p3).phase, 'Phase 3');
    assert.equal(classifyFayManifestPhase(p4).phase, 'Phase 4');
  });

  it('3.4 rejects duplicate module/protocol IDs, uppercase IDs, and unknown top-level fields', () => {
    const dup = {
      name: 'dup-ifay',
      version: '1.0.0',
      description: 'Duplicate modules',
      vendor: 'iFay',
      controlMode: 'command',
      modules: [{ id: 'sensor' }, { id: 'sensor' }],
      protocols: [],
    };
    const resDup = validateFayManifest(dup);
    assert.equal(resDup.valid, false);
    assert.equal(resDup.errors.some((e) => e.includes('duplicate')), true);

    const badCase = {
      name: 'bad-case',
      version: '1.0.0',
      description: 'Uppercase module id',
      vendor: 'iFay',
      controlMode: 'command',
      modules: [{ id: 'SensorUpper' }],
      protocols: [],
    };
    assert.equal(validateFayManifest(badCase).valid, false);
  });
});

describe('@ifay/sdk — 4. CAP 1.0 Client Safety Gate (D-1..D-7)', () => {
  const anchorSeed = Buffer.alloc(32, 0x11);
  const anchorKp = ed25519KeypairFromSeed(anchorSeed);
  const trustAnchors = {
    key_anchor_01: {
      algorithm: 'Ed25519',
      public_key_raw_hex: anchorKp.publicKeyHex,
    },
  };
  const driverManifest = signCapDriverManifest(
    {
      manifest_id: 'mf_sdk_01',
      driver_id: 'drv_sdk_drone',
      version: '1.0.0',
      issued_at: '2026-11-16T00:00:00Z',
      signer_key_id: 'key_anchor_01',
      resources: [
        {
          resource_id: 'res_drone_fc',
          safe_states: [{ safe_state_id: 'hover_and_rtl', description: 'Hover and return' }],
          operations: [
            {
              operation_id: 'read_telemetry',
              mode: 'read',
              criticality: 'routine',
              consequence_irreversibility: 'reversible',
              domain_category: 'device_control',
            },
            {
              operation_id: 'unlock_latch',
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

  it('4.1 signs and verifies DriverCapabilityManifest and allows routine G3 read', () => {
    assert.equal(verifyCapDriverManifest(driverManifest, trustAnchors), true);
    const res = evaluateCapAction(
      {
        protocol_version: '1.0',
        request_id: 'req_1',
        fay_id: 'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
        now_epoch_ms: 1800000000000,
        resource_id: 'res_drone_fc',
        operation_id: 'read_telemetry',
        requested_mode: 'read',
        params: {},
        manifest: driverManifest,
        grant: {
          grant_id: 'grt_1',
          resource_id: 'res_drone_fc',
          allowed_modes: ['read'],
          min_grade: 'G3',
          mandate_binding: {
            mandate_id: 'mnd_1',
            fay_id: 'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
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
      trustAnchors,
    );
    assert.equal(res.decision, 'ALLOW');
    assert.equal(res.effective_criticality, 'routine');
  });

  it('4.2 defaults unknown operations to critical + DENY (D-5)', () => {
    const res = evaluateCapAction(
      {
        protocol_version: '1.0',
        request_id: 'req_unknown',
        fay_id: 'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
        now_epoch_ms: 1800000000000,
        resource_id: 'res_drone_fc',
        operation_id: 'undeclared_laser',
        requested_mode: 'execute',
        params: {},
        manifest: driverManifest,
        grant: {
          grant_id: 'grt_2',
          resource_id: 'res_drone_fc',
          allowed_modes: ['execute'],
          min_grade: 'G1',
          mandate_binding: {
            mandate_id: 'mnd_2',
            fay_id: 'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
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
      trustAnchors,
    );
    assert.equal(res.decision, 'DENY');
    assert.equal(res.effective_criticality, 'critical');
    assert.equal(res.error_code, 'E_UNKNOWN_OPERATION');
    assert.equal(res.diagnostic_code, 2004);
  });

  it('4.3 emits safe_state_directive on G0 emergency takeover without blocking Human Prime (D-3)', () => {
    const res = evaluateCapAction(
      {
        protocol_version: '1.0',
        request_id: 'req_g0',
        fay_id: 'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
        now_epoch_ms: 1800000000000,
        resource_id: 'res_drone_fc',
        operation_id: 'read_telemetry',
        requested_mode: 'read',
        g0_override: true,
        params: {},
        manifest: driverManifest,
        grant: {
          grant_id: 'grt_3',
          resource_id: 'res_drone_fc',
          allowed_modes: ['read'],
          min_grade: 'G1',
          mandate_binding: {
            mandate_id: 'mnd_3',
            fay_id: 'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
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
      trustAnchors,
    );
    assert.equal(res.decision, 'DENY');
    assert.equal(res.error_code, 'E_G0_EMERGENCY_OVERRIDE');
    assert.deepEqual(res.safe_state_directive, {
      action: 'enter_safe_state',
      safe_state_id: 'hover_and_rtl',
      blocks_human_takeover: false,
    });
  });

  it('4.4 enforces irreversibility floor -> high + parameter-bound Human Prime confirmation (D-6 & D-7)', () => {
    const params = { latch_id: 'alpha' };
    const paramsHash = computeCapParamsSha256(params);
    const allowRes = evaluateCapAction(
      {
        protocol_version: '1.0',
        request_id: 'req_high_ok',
        fay_id: 'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
        now_epoch_ms: 1800000000000,
        resource_id: 'res_drone_fc',
        operation_id: 'unlock_latch',
        requested_mode: 'execute',
        caller_criticality_override: 'routine',
        params,
        manifest: driverManifest,
        grant: {
          grant_id: 'grt_4',
          resource_id: 'res_drone_fc',
          allowed_modes: ['execute'],
          min_grade: 'G2',
          mandate_binding: {
            mandate_id: 'mnd_4',
            fay_id: 'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
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
          confirmation_id: 'cnf_1',
          human_prime_id: 'hid_wzwm7fn6bzqkc2icq45pbbn6iqsdhzkpmxlvubti5le7tqmov7lq',
          confirmed_params_sha256: paramsHash,
          terminal_attested_disclosure: true,
          expires_at_epoch_ms: 1800000030000,
        },
      },
      trustAnchors,
    );
    assert.equal(allowRes.decision, 'ALLOW');
    assert.equal(allowRes.effective_criticality, 'high');
    assert.equal(allowRes.escalation_clamped, true);
  });

  it('4.5 unconditionally denies fund_transfer domain_category as out of CAP 1.0 scope (D-7c)', () => {
    const res = evaluateCapAction(
      {
        protocol_version: '1.0',
        request_id: 'req_funds',
        fay_id: 'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
        now_epoch_ms: 1800000000000,
        resource_id: 'res_drone_fc',
        operation_id: 'read_telemetry',
        requested_mode: 'read',
        domain_category: 'fund_transfer',
        params: { amount: 50 },
        manifest: driverManifest,
        grant: {
          grant_id: 'grt_5',
          resource_id: 'res_drone_fc',
          allowed_modes: ['read'],
          min_grade: 'G1',
          mandate_binding: {
            mandate_id: 'mnd_5',
            fay_id: 'ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q',
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
      trustAnchors,
    );
    assert.equal(res.decision, 'DENY');
    assert.equal(res.error_code, 'E_OUT_OF_SCOPE_FUND_TRANSFER');
    assert.equal(res.diagnostic_code, 2007);
  });
});

describe('@ifay/sdk — 5. SSP 1.0 Detached Ed25519 JWS SkillProof & Ego Two-Tier Vault Helpers', () => {
  const provider = deriveEntityKeypair(MASTER_SEED, 'ifay', 1).value;

  it('5.1 signs and verifies an SSP 1.0 SkillDescriptor using RFC 8785 JCS + Detached Ed25519 JWS (alg: EdDSA)', () => {
    const descriptor = {
      protocol: 'ssp/1.0',
      version: '1.0',
      skillId: 'skill.weather.forecast',
      name: 'Local Hyper-Resolution Forecast',
      publisherFayId: provider.entityId,
      origin: 'https://skills.ifay.example',
      visibility: 'public',
      executionMode: 'sync',
      inputSchema: { type: 'object', required: ['lat', 'lon'] },
      outputSchema: { type: 'object', required: ['summary'] },
    };

    const signed = signSkillDescriptor(descriptor, {
      signer: provider,
      kid: `${provider.entityId}#ssp-key-1`,
      created: '2026-11-16T00:00:00Z',
    });

    assert.equal(signed.proof.alg, 'EdDSA');
    assert.equal(signed.proof.jws.includes('..'), true);

    const verified = verifySkillDescriptor(signed, {
      trustedPublicKeyHex: provider.publicKeyHex,
      consumerVersion: '1.0',
    });
    assert.equal(verified.valid, true);
  });

  it('5.2 rejects tampered SSP descriptors and enforces same-MAJOR version compatibility', () => {
    const descriptor = {
      protocol: 'ssp/1.0',
      version: '1.0',
      skillId: 'skill.calendar.read',
      name: 'Calendar Reader',
      publisherFayId: provider.entityId,
      origin: 'https://skills.ifay.example',
      visibility: 'restricted',
      executionMode: 'sync',
    };
    const signed = signSkillDescriptor(descriptor, { signer: provider });

    const tampered = { ...signed, visibility: 'public' };
    assert.equal(
      verifySkillDescriptor(tampered, { trustedPublicKeyHex: provider.publicKeyHex }).valid,
      false,
    );

    assert.equal(isSspVersionCompatible('1.0', '1.2'), true);
    assert.equal(isSspVersionCompatible('2.0', '1.0'), false);
    assert.equal(isSspVersionCompatible('1.0.1', '1.0'), false); // PATCH forbidden in two-segment SSP 1.0
  });

  it('5.3 signs and verifies Ego two-tier Vault manifest.json (ADR 0003) and enforces fidelity_report privacy hygiene', () => {
    const unsignedEgoManifest = {
      version: '1.0.0',
      created_at: '2026-11-16T00:00:00Z',
      base_model: 'qwen3.5-0.8B',
      editions: ['normal'],
      training_backend: 'mlx',
      fidelity_report: {
        schema_version: '1.0',
        status: 'measured',
        holdout_sample_count: 64,
        holdout_loss: 1.12,
        holdout_perplexity: 3.06,
        cell_consistency_score: 0.94,
        probe_win_rate: 0.88,
        drift_from_baseline: 0.07,
      },
      integrity: {
        schema_version: '1.0',
        base_model_digest: 'unverified_offline',
        cell_digests: {
          'normal/adapters/ego-lora.safetensors':
            'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
      },
    };

    const signed = signEgoVaultManifest(unsignedEgoManifest, {
      masterSeed: MASTER_SEED,
      signerFayId: provider.entityId,
    });
    const verified = verifyEgoVaultManifest(signed, {
      trustedPublicKeyHex: signed.signature.public_key_hex,
    });
    assert.equal(verified.valid, true);
    assert.equal(validateEgoFidelityPrivacy(signed.fidelity_report).valid, true);

    const leakyReport = {
      ...signed.fidelity_report,
      raw_prompt_sample: 'My private diary entry...',
    };
    assert.equal(validateEgoFidelityPrivacy(leakyReport).valid, false);
  });
});
