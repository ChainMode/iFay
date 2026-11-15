# Tutorial: Build and Verify a Local iFay Client Node in 15 Minutes

This hands-on tutorial walks developers and Host engineers through assembling, authorizing, and certifying a **Phase 2 (Direct Client Takeover)** iFay client node from scratch using the official zero-dependency `@ifay/sdk` and `@ifay/ifacts` packages included in the `ifay` umbrella repository.

---

## Prerequisites

- **Node.js `>= 20.0.0`** (uses only built-in `node:crypto`, `node:fs`, and `node:test`—zero external runtime dependencies or network installs required).
- Clone the `ifay` repository and enter the workspace root:

```bash
git clone https://github.com/ChainMode/iFay.git
cd iFay
```

---

## Step 1: Run the Built-In Conformance Self-Test (2 Minutes)

Before writing your own node script, verify your local environment with the `ifacts` conformance CLI:

```bash
node packages/ifacts-harness/bin/ifacts.mjs --self-test
```

You should see the progressive `L1 → L2 → L3` gate summary:

```text
[iFACTS] Report Format : ifacts-report/1.0
[iFACTS] Subject       : ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q
[iFACTS] Resolved Phase: Phase 2
[iFACTS] L1 Status     : passed (6/6)
[iFACTS] L2 Status     : passed (4/4)
[iFACTS] L3 Status     : passed (7/7)
[iFACTS] L4 Status     : deferred_phase_4_behavioral
[iFACTS] iFay Ready    : Gold
[iFACTS] Overall       : PASSED
```

---

## Step 2: Derive Canonical Human Prime and iFay Identities (3 Minutes)

Every Individual Fay (`ifay_`) operates strictly on behalf of an explicit **Human Prime** (`hid_`). Both identifiers follow canonical RFC 4648 lowercase no-pad Base32 encoding and derive domain-separated Ed25519 Holder-of-Key keypairs via HKDF-SHA256.

Create a local script (for example `/tmp/quickstart-client.mjs` or a script in your workspace importing `./packages/ifay-sdk/src/index.mjs`):

```javascript
import { randomBytes } from 'node:crypto';
import {
  deriveEntityKeypair,
  createFayManifest,
  validateFayManifest,
  resolveFayManifestDependencies,
  classifyFayManifestPhase,
  createFayingMandate,
  verifyFayingMandate,
  toCapMandateBinding,
  ed25519KeypairFromSeed,
  signCapDriverManifest,
  evaluateCapAction,
  encodeDtpFrame,
  decodeDtpFrame,
} from './packages/ifay-sdk/src/index.mjs';
import { runIfactsSuite } from './packages/ifacts-harness/src/index.mjs';

// 1. Generate a 32-byte master seed for local experimentation
//    (store production seeds inside an OS keychain or hardware security module)
const masterSeed = randomBytes(32);

// 2. Derive Human Prime (hid_) and Individual Fay (ifay_) entity keypairs
const humanPrime = deriveEntityKeypair(masterSeed, 'hid', 0).value;
const myIfay = deriveEntityKeypair(masterSeed, 'ifay', 0).value;

console.log('Human Prime ID :', humanPrime.entityId);
console.log('iFay ID        :', myIfay.entityId);
```

---

## Step 3: Assemble and Validate a `FayManifest` (3 Minutes)

With `createFayManifest`, you declare only the business modules and protocols your client needs (for example `device_driver_hub` + `sensor` over `cap_protocol` + `dtp_protocol` to inhabit a desktop Host). The SDK validates your manifest against `schema/faymanifest/faymanifest.schema.json`, classifies its architectural phase, and automatically completes the 7 required core infrastructure modules:

```javascript
const manifest = createFayManifest({
  name: 'workstation-companion-node',
  version: '0.1.0',
  description: 'Local iFay client node inhabiting a desktop Host workstation',
  vendor: 'Example Lab',
  fayId: myIfay.entityId,
  controlMode: 'ego',
  modules: ['device_driver_hub', 'sensor'],
  protocols: ['cap_protocol', 'dtp_protocol'],
  drivers: [
    {
      name: 'DesktopTelemetryDriver',
      type: 'workstation',
      driverPackage: '@ifay-drivers/desktop-telemetry',
    },
  ],
  ego: {
    modelSource: '@ifay-ego/workstation-base',
    scenarioTags: ['desktop', 'offline-control'],
  },
});

const validation = validateFayManifest(manifest);
const resolvedDeps = resolveFayManifestDependencies(manifest);
const phaseInfo = classifyFayManifestPhase(manifest);

console.log('Manifest valid            :', validation.valid);
console.log('Resolved roadmap phase    :', phaseInfo.phase); // Phase 2
console.log('Auto-completed infra      :', resolvedDeps.autoCompletedModules);
```

---

## Step 4: Issue a `Faying 1.0` Mandate and Enforce the `CAP 1.0` Safety Gate (4 Minutes)

An iFay MUST NEVER invoke Host hardware or software capabilities without explicit, verifiable intent from its Human Prime. Next, we:
1. Sign a `G2` `Faying 1.0` Mandate envelope scoped to a specific Host resource and TTL;
2. Sign and verify a `DriverCapabilityManifest`;
3. Evaluate both a routine `read` operation (`ALLOW`) and a `G0` Human Prime emergency takeover (`DENY` + `safe_state_directive`, with `blocks_human_takeover: false`):

```javascript
const nowMs = Date.now();

// 1. Human Prime signs a G2 Mandate envelope
const mandate = createFayingMandate(
  {
    mandateId: 'mnd_workstation_001',
    humanPrimeId: humanPrime.entityId,
    fayId: myIfay.entityId,
    grade: 'G2',
    scope: {
      resources: ['res_workstation_sensor'],
      actions: ['read'],
      domains: ['local://workstation'],
      terminals: ['host:desktop:primary'],
    },
    deviceId: 'host:desktop:primary',
    issuedAtEpochMs: nowMs,
    expiresAtEpochMs: nowMs + 10 * 60 * 1000,
  },
  humanPrime,
);

const mandateCheck = verifyFayingMandate(mandate, {
  trustedIssuerPublicKeyHex: humanPrime.publicKeyHex,
  nowEpochMs: nowMs + 1000,
  requiredResource: 'res_workstation_sensor',
  requiredAction: 'read',
});
console.log('Faying Mandate verified :', mandateCheck);

// 2. Sign a Host DriverCapabilityManifest
const driverVendorSeed = randomBytes(32);
const driverVendorKey = ed25519KeypairFromSeed(driverVendorSeed);
const trustAnchors = {
  vendor_key_01: {
    algorithm: 'Ed25519',
    public_key_raw_hex: driverVendorKey.publicKeyHex,
  },
};

const driverManifest = signCapDriverManifest(
  {
    manifest_id: 'mf_desktop_01',
    driver_id: 'drv_desktop_telemetry',
    version: '1.0.0',
    issued_at: new Date(nowMs).toISOString(),
    signer_key_id: 'vendor_key_01',
    resources: [
      {
        resource_id: 'res_workstation_sensor',
        safe_states: [{ safe_state_id: 'standby_readonly', description: 'Return to read-only standby' }],
        operations: [
          {
            operation_id: 'read_cpu_thermals',
            mode: 'read',
            criticality: 'routine',
            consequence_irreversibility: 'reversible',
            domain_category: 'device_control',
          },
        ],
      },
    ],
  },
  driverVendorSeed,
);

// 3. Evaluate routine read -> ALLOW
const allowDecision = evaluateCapAction(
  {
    protocol_version: '1.0',
    request_id: 'req_01',
    fay_id: myIfay.entityId,
    now_epoch_ms: nowMs + 1000,
    resource_id: 'res_workstation_sensor',
    operation_id: 'read_cpu_thermals',
    requested_mode: 'read',
    params: {},
    manifest: driverManifest,
    grant: {
      grant_id: 'grt_01',
      resource_id: 'res_workstation_sensor',
      allowed_modes: ['read'],
      min_grade: 'G2',
      mandate_binding: toCapMandateBinding(mandate, 'res_workstation_sensor'),
    },
  },
  trustAnchors,
);
console.log('CAP routine read decision :', allowDecision.decision); // ALLOW

// 4. Simulate G0 emergency takeover -> preempts automated execution and emits safe_state_directive
const g0Decision = evaluateCapAction(
  {
    protocol_version: '1.0',
    request_id: 'req_02_g0',
    fay_id: myIfay.entityId,
    now_epoch_ms: nowMs + 2000,
    resource_id: 'res_workstation_sensor',
    operation_id: 'read_cpu_thermals',
    requested_mode: 'read',
    g0_override: true,
    params: {},
    manifest: driverManifest,
    grant: {
      grant_id: 'grt_01',
      resource_id: 'res_workstation_sensor',
      allowed_modes: ['read'],
      min_grade: 'G2',
      mandate_binding: toCapMandateBinding(mandate, 'res_workstation_sensor'),
    },
  },
  trustAnchors,
);
console.log('G0 preemption decision :', g0Decision.decision, g0Decision.safe_state_directive);
```

---

## Step 5: Seal a `DTP 1.0` Encrypted Data Frame and Certify via `iFACTS` (3 Minutes)

When the Host streams structured telemetry back to the iFay for personal data guardianship, encode the payload as a `DTP 1.0` frame (RFC 8785 JCS frame header + AES-256-GCM authenticated ciphertext), then run `runIfactsSuite` to certify your manifest across L1–L3:

```javascript
// 1. Seal and decode a DTP 1.0 encrypted frame
const sessionKey = randomBytes(32);
const iv = randomBytes(12);
const frame = encodeDtpFrame(
  {
    version: '1.0',
    channelId: 'ch_thermals_01',
    direction: 'terminal_to_ifay',
    sequence: 1,
    contentType: 'application/json',
  },
  Buffer.from(JSON.stringify({ cpuTempCelsius: 52.4 }), 'utf8'),
  sessionKey,
  iv,
);
const decoded = decodeDtpFrame(frame.wireFrame, sessionKey);
console.log('DTP decrypted payload :', decoded.ok ? decoded.plaintext.toString('utf8') : decoded.errorName);

// 2. Run the progressive L1 -> L2 -> L3 iFACTS conformance suite
const report = runIfactsSuite({
  manifest,
  appCapabilities: {
    capProtocol: true,
    dtpProtocol: true,
    credentialDelegation: true,
  },
});

console.log('iFACTS overall status :', report.overallStatus); // passed
console.log('iFay Ready tier       :', report.ifayReady.tier); // Silver
```

You can also validate any saved `FayManifest` JSON file directly from the command line to emit a machine-readable `ifacts-report/1.0` document:

```bash
node packages/ifacts-harness/bin/ifacts.mjs \
  --manifest schema/faymanifest/examples/drone-controller.faymanifest.json \
  --json
```

> **Note (`iFay` vs. `coFay` Conformance Boundary)**: `iFACTS` certifies Individual Fays (`ifay_`) exclusively. Passing a `cofay_` identifier causes `ifacts` to reject the run immediately with `COFAY_OUT_OF_SCOPE_USE_COFACTS` (exit code `2`), directing Collective Fay verification to the separate `coFACTS` suite.

---

## Next Steps

- Continue to [Bridging MCP and LLM Tools Safely into the iFay Protocol Stack](./building-mcp-with-llms.md) to wrap external MCP tools with `SSP 1.0` `SkillProof` signatures, `ICP 1.0` `.ctx` consent blocks, and `CAP 1.0` gates.
- Explore the full API documentation in [`packages/ifay-sdk/README.md`](../../../packages/ifay-sdk/README.md) and [`packages/ifacts-harness/README.md`](../../../packages/ifacts-harness/README.md).
- [Online Documentation (English)](https://ifay.ai/en/docs/tutorials/building-a-client-node)
