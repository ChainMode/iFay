import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  COFAY_BOUNDARY_ERROR_CODE,
  runIfactsSuite,
  runL1Conformance,
  runL2Conformance,
  runL3Conformance,
  evaluateIfayReadyTier,
  createAuditHashChain,
  verifyAuditHashChain,
} from '../src/index.mjs';

const CLI_PATH = fileURLToPath(new URL('../bin/ifacts.mjs', import.meta.url));

describe('@ifay/ifacts — 1. Explicit coFay / coFACTS Boundary Enforcement', () => {
  it('1.1 rejects cofay_ subjectId immediately with COFAY_OUT_OF_SCOPE_USE_COFACTS', () => {
    const report = runIfactsSuite({
      subjectId: 'cofay_evpjbnstakrrzfrczkok4beidw26pphq2u747pm2znma4svaffxq',
    });
    assert.equal(report.overallStatus, 'rejected_out_of_scope');
    assert.equal(report.errorCode, COFAY_BOUNDARY_ERROR_CODE);
    assert.equal(report.errorCode, 'COFAY_OUT_OF_SCOPE_USE_COFACTS');
    assert.equal(report.levels.L1.status, 'not_applicable_cofay');
  });

  it('1.2 rejects target FayManifest whose fayId is a cofay_ identifier', () => {
    const report = runIfactsSuite({
      manifest: {
        name: 'public-role-bot',
        version: '1.0.0',
        description: 'coFay role instance',
        vendor: 'Civic Org',
        fayId: 'cofay_evpjbnstakrrzfrczkok4beidw26pphq2u747pm2znma4svaffxq',
        modules: [],
        protocols: [],
        controlMode: 'command',
      },
    });
    assert.equal(report.overallStatus, 'rejected_out_of_scope');
    assert.equal(report.errorCode, 'COFAY_OUT_OF_SCOPE_USE_COFACTS');
  });
});

describe('@ifay/ifacts — 2. Strictly Progressive Gate (L1 -> L2 -> L3)', () => {
  it('2.1 blocks L2 and L3 with status "blocked_by_previous_level" when ANY L1 check fails', () => {
    let l2Executed = false;
    let l3Executed = false;
    const report = runIfactsSuite({
      manifest: {
        name: 'broken-ifay',
        version: 'not-semver',
        description: 'Invalid manifest triggers L1 failure',
        vendor: 'Test',
        modules: [],
        protocols: [],
        controlMode: 'command',
      },
      hooks: {
        onL2Start: () => {
          l2Executed = true;
        },
        onL3Start: () => {
          l3Executed = true;
        },
      },
    });

    assert.equal(report.levels.L1.status, 'failed');
    assert.equal(report.levels.L2.status, 'blocked_by_previous_level');
    assert.equal(report.levels.L3.status, 'blocked_by_previous_level');
    assert.equal(report.levels.L2.checks.length, 0);
    assert.equal(report.levels.L3.checks.length, 0);
    assert.equal(l2Executed, false);
    assert.equal(l3Executed, false);
  });

  it('2.2 blocks L3 with status "blocked_by_previous_level" when L1 passes and ANY L2 check fails', () => {
    let l3Executed = false;
    const report = runIfactsSuite({
      injectL2FailureForTest: true,
      hooks: {
        onL3Start: () => {
          l3Executed = true;
        },
      },
    });

    assert.equal(report.levels.L1.status, 'passed');
    assert.equal(report.levels.L2.status, 'failed');
    assert.equal(report.levels.L3.status, 'blocked_by_previous_level');
    assert.equal(report.levels.L3.checks.length, 0);
    assert.equal(l3Executed, false);
  });

  it('2.3 honestly reports L4 behavioral conformance as deferred_phase_4_behavioral', () => {
    const report = runIfactsSuite();
    assert.equal(report.reportFormat, 'ifacts-report/1.0');
    assert.equal(report.levels.L4.status, 'deferred_phase_4_behavioral');
  });
});

describe('@ifay/ifacts — 3. L1 Single-Component Conformance', () => {
  it('3.1 passes L1 checks on official FayManifest fixtures, FayID crypto, and signed Ego manifest', () => {
    const l1 = runL1Conformance();
    assert.equal(l1.status, 'passed');
    assert.ok(l1.passedCount >= 6);
    assert.equal(l1.failedCount, 0);
  });

  it('3.2 fails L1 when Ego fidelity_report leaks raw Human Prime text', () => {
    const l1 = runL1Conformance({
      egoManifestOverride: {
        fidelity_report: {
          schema_version: '1.0',
          status: 'measured',
          holdout_sample_count: 10,
          holdout_loss: 1.0,
          holdout_perplexity: 2.7,
          cell_consistency_score: 0.9,
          probe_win_rate: 0.85,
          drift_from_baseline: 0.05,
          raw_corpus_excerpt: 'Secret private chat transcript',
        },
      },
    });
    assert.equal(l1.status, 'failed');
    assert.equal(
      l1.checks.some((c) => c.id === 'L1-EGO-PRIVACY-HYGIENE' && !c.passed),
      true,
    );
  });

  it('3.3 fails L1 when Ego two-tier manifest signature is tampered', () => {
    const l1 = runL1Conformance({
      tamperEgoSignature: true,
    });
    assert.equal(l1.status, 'failed');
    assert.equal(
      l1.checks.some((c) => c.id === 'L1-EGO-TWO-TIER-SIGNATURE' && !c.passed),
      true,
    );
  });
});

describe('@ifay/ifacts — 4. L2 Cross-Protocol Interface Conformance', () => {
  it('4.1 verifies CAP 1.0 D-1..D-7 vectors (sibling repo when present)', () => {
    const l2 = runL2Conformance();
    assert.equal(l2.status, 'passed');
    const capCheck = l2.checks.find((c) => c.id === 'L2-CAP-D1-D7-VECTORS');
    assert.ok(capCheck);
    assert.equal(capCheck.passed, true);
  });

  it('4.2 verifies DTP 1.0 JCS wire format + AES-256-GCM positive and negative vectors', () => {
    const l2 = runL2Conformance();
    const dtpCheck = l2.checks.find((c) => c.id === 'L2-DTP-WIRE-AES-GCM-VECTORS');
    assert.ok(dtpCheck);
    assert.equal(dtpCheck.passed, true);
  });

  it('4.3 verifies FayID subkey derivation, blind gmcref_, and single-parent hierarchy vectors', () => {
    const l2 = runL2Conformance();
    const fayidCheck = l2.checks.find((c) => c.id === 'L2-FAYID-CRYPTO-HIERARCHY-VECTORS');
    assert.ok(fayidCheck);
    assert.equal(fayidCheck.passed, true);
  });

  it('4.4 verifies built-in SSP 1.0 Detached Ed25519 JWS positive and negative vectors cleanly', () => {
    const l2 = runL2Conformance();
    const sspCheck = l2.checks.find((c) => c.id === 'L2-SSP-SIGNED-DESCRIPTOR-VECTORS');
    assert.ok(sspCheck);
    assert.equal(sspCheck.passed, true);
  });

  it('4.5 passes L2 in standalone clone mode using built-in fallback fixtures when sibling repos are absent', () => {
    const l2 = runL2Conformance({ disableSiblingRepoLookup: true });
    assert.equal(l2.status, 'passed');
    assert.equal(
      l2.checks.every((c) => c.vectorSource === 'builtin_fallback'),
      true,
    );
  });
});

describe('@ifay/ifacts — 5. L3 End-to-End Integration Lifecycle & SHA-256 Audit Chain', () => {
  it('5.1 executes full Phase 1/2 E2E flow (Human Prime -> FayID -> Mandate -> FayManifest -> CAP -> DTP -> Ego -> Audit Chain)', () => {
    const l3 = runL3Conformance();
    assert.equal(l3.status, 'passed');
    assert.ok(l3.passedCount >= 7);
    assert.equal(l3.failedCount, 0);
    assert.equal(l3.auditTrail.length >= 6, true);
  });

  it('5.2 cryptographically verifies SHA-256 hash-chained audit trail and detects tampering', () => {
    const chain = createAuditHashChain();
    chain.append('FAYING_HANDSHAKE', { mandateId: 'mnd_01', grade: 'G2' });
    chain.append('CAP_DECISION', { operationId: 'unlock_latch', decision: 'ALLOW' });
    chain.append('DTP_FRAME_SEALED', { fragmentId: 'frag_01', bytes: 96 });

    const entries = chain.entries();
    assert.equal(verifyAuditHashChain(entries).valid, true);

    const tampered = structuredClone(entries);
    tampered[1].payload.decision = 'DENY';
    const check = verifyAuditHashChain(tampered);
    assert.equal(check.valid, false);
    assert.equal(check.brokenIndex, 1);
  });
});

describe('@ifay/ifacts — 6. iFay Ready Certification Tiers & CLI Self-Test', () => {
  it('6.1 awards None tier when baseline UI operability or protocol gates are unmet', () => {
    const res = evaluateIfayReadyTier(
      { firstPersonTracer: false, simulatedOperation: false },
      { L1: 'passed', L2: 'passed', L3: 'passed' },
    );
    assert.equal(res.tier, 'None');
  });

  it('6.2 awards Bronze tier for UI simulated operation (First-person Tracer + Simulated Operation)', () => {
    const res = evaluateIfayReadyTier(
      { firstPersonTracer: true, simulatedOperation: true },
      { L1: 'passed', L2: 'not_requested', L3: 'not_requested' },
    );
    assert.equal(res.tier, 'Bronze');
  });

  it('6.3 awards Silver tier for CAP + DTP + Credential Delegation with L1+L2 passed (and downgrades if L2 fails)', () => {
    const silver = evaluateIfayReadyTier(
      {
        firstPersonTracer: true,
        simulatedOperation: true,
        capProtocol: true,
        dtpProtocol: true,
        credentialDelegation: true,
      },
      { L1: 'passed', L2: 'passed', L3: 'not_requested' },
    );
    assert.equal(silver.tier, 'Silver');

    const downgraded = evaluateIfayReadyTier(
      {
        firstPersonTracer: true,
        simulatedOperation: true,
        capProtocol: true,
        dtpProtocol: true,
        credentialDelegation: true,
      },
      { L1: 'passed', L2: 'failed', L3: 'blocked_by_previous_level' },
    );
    assert.equal(downgraded.tier, 'Bronze');
  });

  it('6.4 awards Gold tier for SSP + C/F/S full integration when L1 + L2 + L3 all pass', () => {
    const report = runIfactsSuite({
      appCapabilities: {
        firstPersonTracer: true,
        simulatedOperation: true,
        capProtocol: true,
        dtpProtocol: true,
        credentialDelegation: true,
        sspProtocol: true,
        cfsIntegration: true,
      },
    });
    assert.equal(report.overallStatus, 'passed');
    assert.equal(report.ifayReady.tier, 'Gold');
  });

  it('6.5 CLI --self-test exits 0 with ifacts-report/1.0 JSON and rejects cofay_ targets with exit code 2', () => {
    const stdout = execFileSync(process.execPath, [CLI_PATH, '--self-test', '--json'], {
      encoding: 'utf8',
    });
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.reportFormat, 'ifacts-report/1.0');
    assert.equal(parsed.overallStatus, 'passed');
    assert.equal(parsed.ifayReady.tier, 'Gold');

    let exitCode = 0;
    let errOut = '';
    try {
      execFileSync(
        process.execPath,
        [CLI_PATH, '--target-fay-id', 'cofay_evpjbnstakrrzfrczkok4beidw26pphq2u747pm2znma4svaffxq'],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
      );
    } catch (err) {
      exitCode = err.status;
      errOut = `${err.stdout ?? ''}${err.stderr ?? ''}`;
    }
    assert.equal(exitCode, 2);
    assert.equal(errOut.includes('COFAY_OUT_OF_SCOPE_USE_COFACTS'), true);
  });
});
