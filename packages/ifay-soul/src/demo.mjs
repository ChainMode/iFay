import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { deriveEntityKeypair } from '@ifay/sdk';
import { CofaySeatBuilder } from './cofay-seat.mjs';
import { packDtpPersonalContextFrame } from './ifay-profile.mjs';
import { PrimaryBodyStore, syncPrimaryReplicas } from './primary-body.mjs';
import {
  OFFICIAL_DEVICE_PROFILES,
   sliceSoulForDevice,
  verifyRemotePrimaryPointer,
} from './slicer.mjs';

export function runSoulDemo(options = {}) {
  const seedA = createHash('sha256').update('ifay-soul-demo-human-prime-v1').digest();
  const seedB = createHash('sha256').update('ifay-soul-demo-next-steward-v1').digest();

  // 1. Initialize Primary Body Replica A (Home Workstation) — stealth by default
  const replicaA = PrimaryBodyStore.init({
    masterSeed: seedA,
    replicaId: 'replica:home-mac-nvme',
    displayName: 'Alex Digital Soul',
    createdAt: '2026-11-20T09:00:00.000Z',
  });

  // 2. Clone Peer Primary Body Replica B (Home NAS / Cloud Sync Folder)
  const replicaB = PrimaryBodyStore.createPeerReplica(replicaA, {
    replicaId: 'replica:nas-mirror',
  });

  // 3. Concurrent embodiment commits across peer replicas:
  //    - Laptop embodiment ingests an encrypted DTP 1.0 personal note into Replica A
  const dtpSessionKey = createHash('sha256').update('demo-dtp-session-key').digest();
  const dtpIv = Buffer.from('000102030405060708090a0b', 'hex');
  const dtpFrame = packDtpPersonalContextFrame(
    {
      senderFayId: replicaA.fayId,
      sessionId: 'sess_laptop_notes_01',
      sequenceNumber: 1,
      timestampMs: Date.parse('2026-11-20T09:05:00.000Z'),
      subtype: 'knowledge_base',
      title: 'Zero-Copy BuF Lazy Section Loading Notes',
      text: 'Skeleton parse reads [0, sections_offset) + 44B trailer before lazy section fetches.',
      domain: 'engineering',
      tags: ['buf', 'fayger', 'rust'],
    },
    dtpSessionKey,
    dtpIv,
  );
  replicaA.ingestDtpFrame(dtpFrame.wireFrame, dtpSessionKey, {
    originDeviceId: 'embodiment:laptop-plus-01',
    timestamp: '2026-11-20T09:05:00.000Z',
  });

  //    - Opt-in platform registration on Replica A (expert registry)
  replicaA.registerPlatform(
    {
      platformId: 'expert.systems-architects',
      category: 'expert',
      handleOrRef: '@alex.systems',
      discoverable: true,
    },
    {
      originDeviceId: 'embodiment:laptop-plus-01',
      timestamp: '2026-11-20T09:06:00.000Z',
    },
  );

  //    - Mobile embodiment offline records a Human Prime correction + switches Ego on Replica B
  replicaB.recordHumanCorrection(
    {
      promptContext: 'Draft Friday team status email',
      rejectedOutput: 'Verbose 6-paragraph corporate update with filler',
      preferredOutput: '3 bullet points: shipped, metrics, blockers',
      extractedRule: 'Keep status emails to <= 3 concise bullet points with concrete metrics',
      sourceDeviceId: 'embodiment:mobile-normal-01',
    },
    { timestamp: '2026-11-20T09:05:30.000Z' },
  );

  // 4. Reconcile Peer Primary Bodies (Replica A <-> Replica B)
  const syncReport = syncPrimaryReplicas(replicaA, replicaB);

  // 5. Adaptive .buf Embodiment Slicing across 3 DeviceRuntimeProfile tiers
  const superSlice = sliceSoulForDevice(replicaA, OFFICIAL_DEVICE_PROFILES.super);
  const liteSlice = sliceSoulForDevice(replicaA, OFFICIAL_DEVICE_PROFILES.lite);
  const thinSlice = sliceSoulForDevice(replicaA, OFFICIAL_DEVICE_PROFILES.thin);
  const pointerVerified = verifyRemotePrimaryPointer(
    thinSlice.remotePrimaryPointer,
    replicaA.profile.identity.entity_public_key_hex,
  );

  // 6. Build coFay Project Collaborator Seat + Dual-Signed Atomic Ownership Transfer
  const cofaySeat = CofaySeatBuilder.createSeat({
    masterSeed: seedA,
    roleArchetype: 'project_collaborator',
    orgSlug: 'ifay-open-source',
    displayName: 'iFay OSS Triage coFay Seat',
    issuedAt: '2026-11-20T09:10:00.000Z',
  });

  const nextStewardKp = deriveEntityKeypair(seedB, 'hid', 0);
  const nextOrgKp = deriveEntityKeypair(seedB, 'org', 'chainmode-maintainers');
  const transferEnvelope = CofaySeatBuilder.createTransferEnvelope(cofaySeat.role_charter, {
    toOwner: { type: 'organization', id: nextOrgKp.value.entityId },
    newStewardHumanId: nextStewardKp.value.entityId,
    managerPolicy: 'CLEAR_ALL',
    fromSeed: seedA,
    toSeed: seedB,
    initiatedAt: '2026-11-20T09:15:00.000Z',
    expiresAt: '2026-11-21T09:15:00.000Z',
  });
  const transferOutcome = CofaySeatBuilder.applyOwnershipTransfer(
    cofaySeat.role_charter,
    transferEnvelope,
    { nextOwnerSeed: seedB },
  );
  const cofayBuf = CofaySeatBuilder.packSeatBuf({
    ...cofaySeat,
    role_charter: transferOutcome.nextCharter,
  });

  let writtenFiles = null;
  if (options.outDir) {
    const outAbs = resolve(options.outDir);
    mkdirSync(outAbs, { recursive: true });
    writeFileSync(join(outAbs, 'ifay-workstation-super.buf'), superSlice.bufBytes);
    writeFileSync(join(outAbs, 'ifay-drone-lite.buf'), liteSlice.bufBytes);
    writeFileSync(join(outAbs, 'ifay-watch-thin.buf'), thinSlice.bufBytes);
    writeFileSync(join(outAbs, 'cofay-project-collaborator.buf'), cofayBuf);
    writtenFiles = {
      outDir: outAbs,
      files: [
        'ifay-workstation-super.buf',
        'ifay-drone-lite.buf',
        'ifay-watch-thin.buf',
        'cofay-project-collaborator.buf',
      ],
    };
  }

  return {
    fayId: replicaA.fayId,
    humanPrimeId: replicaA.profile.identity.human_prime_id,
    visibilityMode: replicaA.profile.identity.visibility_mode,
    activePersona: replicaA.profile.ego.active_persona_id,
    humanCorrectionsRecorded: replicaA.profile.ego.human_corrections.length,
    syncReport,
    slices: {
      super: superSlice.sliceSummary,
      lite: liteSlice.sliceSummary,
      thin: { ...thinSlice.sliceSummary, pointerVerified },
    },
    cofay: {
      cofayId: cofaySeat.cofay_id,
      archetype: cofaySeat.role_charter.role_archetype,
      transferredToOwner: transferOutcome.nextCharter.owner.id,
      transferNonce: transferOutcome.nextCharter.transfer_nonce,
      bufByteLength: cofayBuf.length,
    },
    writtenFiles,
  };
}

export function formatSoulDemoReport(result) {
  const lines = [
    '======================================================================',
    '  @ifay/soul — Portable Digital Soul, Peer Sync & BuF Slicer Demo',
    '======================================================================',
    `[1] 6-Dimension iFay Primary Body Initialized`,
    `    Human Prime ID       : ${result.humanPrimeId}`,
    `    iFay Soul ID         : ${result.fayId}`,
    `    Active Ego Persona   : ${result.activePersona} (strictly 1 active invariant)`,
    `    Discovery Mode       : ${result.visibilityMode} (opt-in platform attestation verified)`,
    `    Ego School Alignments: ${result.humanCorrectionsRecorded} Human Prime correction(s)`,
    '',
    `[2] Peer-to-Peer Primary Body Ledger Sync (Replica A <-> Replica B)`,
    `    Merged Causal Events : ${result.syncReport.totalEvents} (pulled A<-B: ${result.syncReport.pulledIntoA}, B<-A: ${result.syncReport.pulledIntoB})`,
    `    Replica Consistency  : ${result.syncReport.consistent ? '100% IDENTICAL' : 'MISMATCH'}`,
    `    State Root SHA-256   : ${result.syncReport.stateRootSha256}`,
    '',
    `[3] Adaptive FayGer .buf Embodiment Slicing (BUF\\0 v1 + Canonical CBOR + CRC32)`,
    `    Workstation (super)  : ${result.slices.super.bufByteLength} B | thoughts=${result.slices.super.bundledThoughts}/${result.slices.super.totalPrimaryThoughts}, skills=${result.slices.super.bundledSkills}, personas=${result.slices.super.bundledPersonas}`,
    `    Edge Drone (lite)    : ${result.slices.lite.bufByteLength} B | thoughts=${result.slices.lite.bundledThoughts}/${result.slices.lite.totalPrimaryThoughts}, skills=${result.slices.lite.bundledSkills}, compact LoRA slice`,
    `    Ultra-Thin (thin)    : ${result.slices.thin.bufByteLength} B | thoughts=${result.slices.thin.bundledThoughts}, localEgo=${result.slices.thin.localEgoWeightsBundled}, signedPointer=${result.slices.thin.pointerVerified}`,
    '',
    `[4] coFay Accountable Public Seat & Dual-Signed TransferEnvelope 1.0`,
    `    coFay Seat ID        : ${result.cofay.cofayId} [${result.cofay.archetype}]`,
    `    Atomic Transfer To   : ${result.cofay.transferredToOwner} (nonce=${result.cofay.transferNonce})`,
    `    coFay Seat BuF Size  : ${result.cofay.bufByteLength} B`,
    '======================================================================',
  ];
  if (result.writtenFiles) {
    lines.push(`Wrote ${result.writtenFiles.files.length} .buf artifacts to ${result.writtenFiles.outDir}`);
  }
  return lines.join('\n');
}
