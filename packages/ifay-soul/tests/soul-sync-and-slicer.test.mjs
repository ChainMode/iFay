import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { deriveEntityKeypair } from '@ifay/sdk';
import {
  CofaySeatBuilder,
  OFFICIAL_DEVICE_PROFILES,
  PrimaryBodyStore,
  packDtpPersonalContextFrame,
  parseBufBinary,
  runSoulDemo,
  sliceSoulForDevice,
  syncPrimaryReplicas,
  validateIfayProfile,
  validateRoleCharter,
  verifyRemotePrimaryPointer,
} from '../src/index.mjs';

const CLI_BIN = resolve(import.meta.dirname, '../bin/ifay-soul.mjs');

test('6-Dimension iFay Profile enforces stealth-by-default, opt-in platform registration, single-active-Ego, and DTP ingestion', () => {
  const masterSeed = createHash('sha256').update('test-profile-seed-01').digest();
  const store = PrimaryBodyStore.init({
    masterSeed,
    displayName: 'Lin Soul',
  });

  // Stealth by default
  assert.equal(store.profile.identity.visibility_mode, 'stealth');
  assert.equal(store.profile.identity.platform_registrations.length, 0);

  // Strictly 1 active Ego persona
  assert.equal(store.profile.ego.active_persona_id, 'professional');
  assert.equal(store.profile.ego.personas.filter((p) => p.active).length, 1);

  // Add a 3rd persona & switch active Ego -> still strictly 1 active
  store.addPersona({
    persona_id: 'drone_pilot',
    label: 'Aerial Survey Persona',
    scenario_tags: ['aerial_photography', 'inspection'],
  });
  store.switchActiveEgo('drone_pilot');
  assert.equal(store.profile.ego.active_persona_id, 'drone_pilot');
  assert.equal(store.profile.ego.personas.filter((p) => p.active).length, 1);

  // Violating single-active-Ego invariant in a mutated copy is caught by validateIfayProfile
  const brokenZeroActive = structuredClone(store.profile);
  for (const p of brokenZeroActive.ego.personas) p.active = false;
  assert.equal(validateIfayProfile(brokenZeroActive).valid, false);

  const brokenTwoActive = structuredClone(store.profile);
  brokenTwoActive.ego.personas[0].active = true;
  brokenTwoActive.ego.personas[2].active = true;
  const twoCheck = validateIfayProfile(brokenTwoActive);
  assert.equal(twoCheck.valid, false);
  assert.ok(twoCheck.errors.some((e) => e.startsWith('SINGLE_ACTIVE_EGO_VIOLATION')));

  // Opt-in platform registration transitions visibility_mode -> registered_opt_in, revoke -> stealth
  store.registerPlatform({
    platformId: 'expert.robotics-guild',
    category: 'expert',
    handleOrRef: '@lin.aerial',
    discoverable: true,
  });
  assert.equal(store.profile.identity.visibility_mode, 'registered_opt_in');
  assert.equal(validateIfayProfile(store.profile).valid, true);

  store.revokePlatform('expert.robotics-guild');
  assert.equal(store.profile.identity.visibility_mode, 'stealth');
  assert.equal(validateIfayProfile(store.profile).valid, true);

  // DTP 1.0 encrypted context frame ingestion
  const sessionKey = createHash('sha256').update('dtp-key-1').digest();
  const iv = Buffer.from('aabbccddeeff001122334455', 'hex');
  const frame = packDtpPersonalContextFrame(
    {
      senderFayId: store.fayId,
      sessionId: 'sess_notes_99',
      sequenceNumber: 7,
      subtype: 'data',
      title: 'Field Battery Telemetry Summary',
      text: 'Hover drain 1.4% per minute in 8m/s coastal wind.',
      domain: 'aerial_photography',
    },
    sessionKey,
    iv,
  );
  const ingested = store.ingestDtpFrame(frame.wireFrame, sessionKey);
  assert.equal(ingested.thoughtItem.domain, 'aerial_photography');
  assert.ok(store.profile.thought.data.some((t) => t.title === 'Field Battery Telemetry Summary'));

  // Wrong DTP key fails decryption
  const wrongKey = createHash('sha256').update('wrong-dtp-key').digest();
  assert.throws(() => store.ingestDtpFrame(frame.wireFrame, wrongKey), /DECRYPTION_FAILED/);
});

test('PrimaryBodyStore peer replica sync converges deterministically across 3 replicas and detects tampering', () => {
  const seed = createHash('sha256').update('peer-sync-seed-v1').digest();
  const repA = PrimaryBodyStore.init({
    masterSeed: seed,
    replicaId: 'replica:mac-local',
    createdAt: '2026-11-20T10:00:00.000Z',
  });
  const repB = PrimaryBodyStore.createPeerReplica(repA, { replicaId: 'replica:cloud-drive' });
  const repC = PrimaryBodyStore.createPeerReplica(repA, { replicaId: 'replica:home-nas' });

  // Concurrent offline commits across all 3 replicas
  repA.commitEmbodimentDelta({
    type: 'thought_added',
    deviceId: 'embodiment:workstation',
    timestamp: '2026-11-20T10:01:00.000Z',
    thought: {
      subtype: 'knowledge_base',
      title: 'Consensus Safety Invariants',
      text: 'Quorum intersection prevents split-brain commits.',
      domain: 'engineering',
    },
  });

  repB.commitEmbodimentDelta({
    type: 'human_correction',
    deviceId: 'embodiment:phone',
    timestamp: '2026-11-20T10:01:10.000Z',
    promptContext: 'Schedule 8am meeting',
    rejectedOutput: 'Booked 08:00 meeting',
    preferredOutput: 'Proposed 13:30 slot outside deep-work window',
    extractedRule: 'Never book meetings before 10:00 local time',
  });

  repC.commitEmbodimentDelta({
    type: 'skill_registered',
    deviceId: 'embodiment:tablet',
    timestamp: '2026-11-20T10:01:20.000Z',
    skill: {
      skill_type: 'microservice',
      name: 'Local Whisper Transcriber',
      endpoint_or_package: '@ifay/ms-whisper-local',
      domains: ['productivity'],
      required_capabilities: ['fs.read'],
    },
  });

  // Sync in one order: A <-> B, B <-> C, A <-> C
  const r1 = syncPrimaryReplicas(repA, repB);
  assert.equal(r1.ok, true);
  assert.equal(r1.consistent, true);

  const r2 = syncPrimaryReplicas(repB, repC);
  assert.equal(r2.ok, true);
  assert.equal(r2.consistent, true);

  const r3 = syncPrimaryReplicas(repA, repC);
  assert.equal(r3.ok, true);
  assert.equal(repA.stateRootSha256, repB.stateRootSha256);
  assert.equal(repB.stateRootSha256, repC.stateRootSha256);
  assert.equal(repA.events.length, 4);

  // Tamper detection: mutate a payload field in repC without re-signing
  const tamperedReplica = PrimaryBodyStore.createPeerReplica(repA, { replicaId: 'replica:tampered' });
  tamperedReplica.events[1].payload.thought.text = 'FORGED PAYLOAD';
  const badSync = syncPrimaryReplicas(repA, tamperedReplica);
  assert.equal(badSync.ok, false);
  assert.equal(badSync.errorCode, 'LEDGER_HASH_MISMATCH');

  // Genesis mismatch detection: unrelated soul cannot sync
  const unrelatedSoul = PrimaryBodyStore.init({
    masterSeed: createHash('sha256').update('other-person-seed').digest(),
  });
  const mismatchSync = syncPrimaryReplicas(repA, unrelatedSoul);
  assert.equal(mismatchSync.ok, false);
  assert.equal(mismatchSync.errorCode, 'LEDGER_GENESIS_MISMATCH');
});

test('sliceSoulForDevice adapts across workstation super, edge drone lite, and remote_only thin profiles', () => {
  const seed = createHash('sha256').update('slicer-seed-01').digest();
  const soul = PrimaryBodyStore.init({ masterSeed: seed });

  // Add a secret thought and a correction to verify filtering & Ego School buffer inclusion
  soul.addThought({
    subtype: 'data',
    title: 'Private Recovery Hint',
    text: 'Stored in physical fireproof safe',
    domain: 'aerial_photography',
    sensitivity: 'secret',
  });
  soul.recordHumanCorrection({
    promptContext: 'Drone return-to-home altitude',
    rejectedOutput: 'Set RTH to 15m',
    preferredOutput: 'Set RTH to >= 50m to clear coastal trees',
    extractedRule: 'Minimum RTH altitude is 50m',
  });

  // 1. Super workstation: bundles all 5 thoughts + ego_school_buffer + both personas
  const superOut = sliceSoulForDevice(soul, OFFICIAL_DEVICE_PROFILES.super);
  assert.equal(superOut.mode, 'full_embodiment');
  assert.equal(superOut.sliceSummary.bundledThoughts, 5);
  assert.equal(superOut.sliceSummary.bundledPersonas, 2);
  assert.ok(superOut.parsedBuf.sections.some((s) => s.id === 'ego_school_buffer'));

  // 2. Lite drone: filters out engineering thoughts AND filters out 'secret' thought, bundles compact LoRA slice
  const liteOut = sliceSoulForDevice(soul, OFFICIAL_DEVICE_PROFILES.lite);
  assert.equal(liteOut.mode, 'compact_edge_slice');
  assert.equal(liteOut.sliceSummary.bundledThoughts, 1);
  assert.equal(liteOut.sliceSummary.bundledSkills, 1);
  assert.equal(liteOut.sliceSummary.bundledPersonas, 1);
  assert.equal(liteOut.egoSliceDescriptor.slice_mode, 'compact_distilled_slice');
  assert.ok(liteOut.bufBytes.length < superOut.bufBytes.length);

  // 3. Thin / remote_only watch: zero local thoughts, zero local Ego weights, valid signed pointer
  const thinOut = sliceSoulForDevice(soul, OFFICIAL_DEVICE_PROFILES.thin);
  assert.equal(thinOut.mode, 'remote_primary_pointer');
  assert.equal(thinOut.sliceSummary.bundledThoughts, 0);
  assert.equal(thinOut.sliceSummary.localEgoWeightsBundled, false);
  assert.ok(!thinOut.parsedBuf.sections.some((s) => s.id === 'thought_slice'));
  assert.ok(thinOut.parsedBuf.sections.some((s) => s.id === 'remote_primary_pointer'));
  assert.equal(
    verifyRemotePrimaryPointer(
      thinOut.remotePrimaryPointer,
      soul.profile.identity.entity_public_key_hex,
    ),
    true,
  );

  // Offline remote_only device is rejected as infeasible
  assert.throws(
    () =>
      sliceSoulForDevice(soul, {
        ...OFFICIAL_DEVICE_PROFILES.thin,
        network_online: false,
      }),
    /DEVICE_PROFILE_INFEASIBLE/,
  );
});

test('CofaySeatBuilder supports all 3 RoleCharter 1.0 archetypes, steward rotation, ego boundary guard, and dual-signed transfer', () => {
  const seed1 = createHash('sha256').update('cofay-seed-1').digest();
  const seed2 = createHash('sha256').update('cofay-seed-2').digest();

  for (const archetype of ['org_service', 'functional_post', 'project_collaborator']) {
    const seat = CofaySeatBuilder.createSeat({
      masterSeed: seed1,
      roleArchetype: archetype,
      orgSlug: `team-${archetype.replace(/_/g, '-')}`,
    });
    assert.equal(validateRoleCharter(seat.role_charter).valid, true);
    const buf = CofaySeatBuilder.packSeatBuf(seat);
    const parsed = parseBufBinary(buf);
    assert.equal(parsed.manifest.extensions.fay_entity_kind, 'cofay');
  }

  // Personal Ego attachment is forbidden on coFay RoleCharter
  const seat = CofaySeatBuilder.createSeat({ masterSeed: seed1, roleArchetype: 'org_service' });
  const illegalEgoCharter = { ...seat.role_charter, ego_package: '@ego-models/private' };
  const egoCheck = validateRoleCharter(illegalEgoCharter, { verifySignature: false });
  assert.equal(egoCheck.valid, false);
  assert.ok(egoCheck.errors.some((e) => e.code === 'COFAY_EGO_FORBIDDEN'));

  // Steward rotation
  const steward2 = deriveEntityKeypair(seed2, 'hid', 0).value.entityId;
  const rotated = CofaySeatBuilder.rotateSteward(seat.role_charter, {
    newStewardHumanId: steward2,
    ownerOrCurrentSignerId: steward2,
    signerSeed: seed2,
  });
  assert.equal(validateRoleCharter(rotated).valid, true);
  assert.equal(rotated.steward_human_id, steward2);
  assert.equal(rotated.charter_revision, 2);

  // Dual-signed ownership transfer (TransferEnvelope 1.0)
  const humanOwner2 = deriveEntityKeypair(seed1, 'hid', 3).value.entityId;
  const seedOwner2 = createHash('sha256').update('cofay-human-owner-2').digest();
  const env = CofaySeatBuilder.createTransferEnvelope(rotated, {
    toOwner: { type: 'human', id: humanOwner2 },
    managerPolicy: 'CLEAR_ALL',
    fromSeed: seed2,
    toSeed: seedOwner2,
  });

  // Tamper with to_signature -> rejected
  const brokenEnv = structuredClone(env);
  brokenEnv.to_signature.signature_hex = '00'.repeat(64);
  assert.equal(CofaySeatBuilder.applyOwnershipTransfer(rotated, brokenEnv).valid, false);

  const transferred = CofaySeatBuilder.applyOwnershipTransfer(rotated, env, {
    nextOwnerSeed: seedOwner2,
  });
  assert.equal(transferred.valid, true);
  assert.equal(transferred.nextCharter.owner.id, humanOwner2);
  assert.equal(transferred.nextCharter.transfer_nonce, 1);
  assert.equal(validateRoleCharter(transferred.nextCharter).valid, true);
});

test('ifay-soul CLI executes init, add-thought, record-correction, register-platform, sync, slice, inspect-buf, init-cofay, and demo', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'ifay-soul-cli-e2e-'));
  try {
    const soulA = join(tmp, 'my-soul');
    const soulB = join(tmp, 'my-soul-peer');
    const cofayDir = join(tmp, 'oss-seat');
    const liteBuf = join(tmp, 'dist', 'my-ifay-lite.buf');

    execFileSync(process.execPath, [CLI_BIN, 'init', soulA, '--name', 'CLI Test Soul'], {
      encoding: 'utf8',
    });
    execFileSync(process.execPath, [CLI_BIN, 'sync', soulA, soulB], { encoding: 'utf8' });

    execFileSync(
      process.execPath,
      [
        CLI_BIN,
        'add-thought',
        soulA,
        '--subtype',
        'knowledge_base',
        '--title',
        'Drone Checklist',
        '--text',
        'Verify props and compass calibration.',
        '--domain',
        'aerial_photography',
      ],
      { encoding: 'utf8' },
    );

    execFileSync(
      process.execPath,
      [
        CLI_BIN,
        'record-correction',
        soulB,
        '--prompt',
        'Reply tone',
        '--wrong',
        'Overly formal',
        '--corrected',
        'Direct and friendly',
        '--rule',
        'Keep tone direct',
      ],
      { encoding: 'utf8' },
    );

    execFileSync(
      process.execPath,
      [
        CLI_BIN,
        'register-platform',
        soulA,
        '--platform',
        'expert.aerial-guild',
        '--handle',
        '@cli.pilot',
      ],
      { encoding: 'utf8' },
    );

    const syncOut = execFileSync(process.execPath, [CLI_BIN, 'sync', soulA, soulB], {
      encoding: 'utf8',
    });
    assert.match(syncOut, /consistent:\s+true/);

    execFileSync(
      process.execPath,
      [CLI_BIN, 'slice', soulA, '--tier', 'lite', '--out', liteBuf],
      { encoding: 'utf8' },
    );
    assert.equal(existsSync(liteBuf), true);

    const inspectJson = JSON.parse(
      execFileSync(process.execPath, [CLI_BIN, 'inspect-buf', liteBuf, '--json'], {
        encoding: 'utf8',
      }),
    );
    assert.equal(inspectJson.header.magic, 'BUF\\0');
    assert.equal(inspectJson.verified.digestValid, true);
    assert.equal(inspectJson.verified.crc32Valid, true);

    execFileSync(
      process.execPath,
      [CLI_BIN, 'init-cofay', cofayDir, '--archetype', 'project_collaborator'],
      { encoding: 'utf8' },
    );
    assert.equal(existsSync(join(cofayDir, 'seat.buf')), true);

    const demoResult = runSoulDemo();
    assert.equal(demoResult.syncReport.consistent, true);
    assert.equal(demoResult.slices.thin.pointerVerified, true);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
