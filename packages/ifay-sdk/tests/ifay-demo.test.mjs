import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { formatIfayDemoReport, runIfayDemo } from '../src/demo.mjs';

const CLI_PATH = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

describe('@ifay/sdk — 6. Interactive ifay-demo CLI & Walkthrough', () => {
  it('6.1 executes all 4 cryptographic walkthrough steps deterministically in < 1000ms', async () => {
    const res = await runIfayDemo();
    assert.equal(res.ok, true);
    assert.equal(res.elapsedMs < 1000, true, `expected <1000ms, got ${res.elapsedMs}ms`);

    assert.equal(res.steps.fayIdAndManifest.fayIdKind, 'IFAY_ID');
    assert.equal(res.steps.fayIdAndManifest.fayId.startsWith('ifay_'), true);
    assert.equal(res.steps.fayIdAndManifest.humanPrimeId.startsWith('hid_'), true);
    assert.equal(res.steps.fayIdAndManifest.manifestValid, true);

    assert.equal(res.steps.fayingMandate.valid, true);
    assert.equal(res.steps.fayingMandate.grade, 'G2');

    assert.equal(res.steps.capSafetyGate.allowedAction.decision, 'ALLOW');
    assert.equal(res.steps.capSafetyGate.deniedAction.decision, 'DENY');
    assert.equal(res.steps.capSafetyGate.deniedAction.errorCode, 'E_GRADE_INSUFFICIENT');
    assert.equal(res.steps.capSafetyGate.deniedAction.diagnosticCode, 2002);

    assert.equal(res.steps.ifactsConformance.overallStatus, 'passed');
    assert.equal(res.steps.ifactsConformance.ifayReadyTier, 'Gold');

    const formatted = formatIfayDemoReport(res);
    assert.match(formatted, /\[1\/4\] FayID Root Derivation & FayManifest Inspection/);
    assert.match(formatted, /\[2\/4\] Faying 1.0 Delegation Mandate/);
    assert.match(formatted, /\[3\/4\] Control Authority Protocol \(CAP 1\.0\) Host Safety Gate/);
    assert.match(formatted, /\[4\/4\] iFACTS Progressive Conformance Bundle Verification/);
    assert.match(formatted, /ALL 4 CRYPTOGRAPHIC GATES VERIFIED/);
  });

  it('6.2 runs dist/cli.js via subprocess in human-readable and --json modes', () => {
    const humanOut = execFileSync(process.execPath, [CLI_PATH], { encoding: 'utf8' });
    assert.match(humanOut, /Decision  : ALLOW/);
    assert.match(humanOut, /Decision  : DENY \[E_GRADE_INSUFFICIENT \/ code 2002\]/);
    assert.match(humanOut, /iFay Ready Tier: Gold/);

    const jsonOut = JSON.parse(
      execFileSync(process.execPath, [CLI_PATH, '--json'], { encoding: 'utf8' }),
    );
    assert.equal(jsonOut.ok, true);
    assert.equal(jsonOut.steps.capSafetyGate.allowedAction.decision, 'ALLOW');
    assert.equal(jsonOut.steps.capSafetyGate.deniedAction.decision, 'DENY');
    assert.equal(jsonOut.steps.ifactsConformance.overallStatus, 'passed');
  });
});
