# `@ifay/sdk`

Official zero-dependency client SDK for the **iFay** ecosystem (`Fay = iFay + coFay`).

`@ifay/sdk` wraps the frozen cryptographic, manifest, authorization, safety-gating, and skill-signing primitives so application and Host developers can integrate an `iFay` client in pure Node.js (`>= 20`) with zero external runtime dependencies.

## Capabilities

1. **FayID & Cryptographic Primitives**:
   - Canonical RFC 4648 lowercase unpadded Base32 parsing and validation across all 8 prefixes (`hid_`, `ifay_`, `cofay_`, `org_`, `dyn_`, `grt_`, `vrf_`, `gmcref_`).
   - Deterministic HKDF-SHA256 purpose-subkey derivation (`ifay.fayid.entity.v1`, `ifay.ego.package-signing.v1`, `ifay.gmc.natural-person.v1`) ensuring Human Prime root seed material is never serialized.
   - RFC 8785 JSON Canonicalization Scheme (`canonicalizeJcs`) and Ed25519 Holder-of-Key signing/verification.
2. **Faying 1.0 Handshake & Mandate Helper**:
   - Build, delegate, and verify signed Faying 1.0 Mandate envelopes (`G0`–`G4` authorization grades, scope subset convergence, TTL/revocation enforcement, and `G0` emergency takeover).
3. **Authoritative `FayManifest` Builder & Validator**:
   - Programmatic `createFayManifest(...)`, automatic 7-component infrastructure + conditional `ego_model` dependency completion, governed namespace classification (`@ifay/*`, `@ego-models/*`, `@cap-drivers/*`, `@drone-drivers/*`), `Phase 1`–`Phase 5` classifier, and structural validation against `schema/faymanifest/faymanifest.schema.json`.
4. **CAP 1.0 & SSP 1.0 Client Helpers**:
   - `evaluateCapAction(...)` implementing the `D-1..D-7` safety cluster (undeclared operations default to `critical + DENY`, `G0` triggers non-blocking `safe_state_directive`, and `high`/`critical` operations enforce parameter-bound Human Prime confirmation).
   - `signSkillDescriptor(...)` and `verifySkillDescriptor(...)` producing RFC 8785 JCS + Detached Ed25519 JWS (`alg: "EdDSA"`) `SkillProof` envelopes under two-segment `ssp/1.0`.
   - DTP 1.0 AES-256-GCM wire frame codec (`encodeDtpFrame`, `decodeDtpFrame`) and Ego two-tier Vault `manifest.json` verification (`verifyEgoVaultManifest`, `validateEgoFidelityPrivacy`).

## Quick Example

```js
import { randomBytes } from 'node:crypto';
import {
  deriveEntityKeypair,
  createFayingMandate,
  verifyFayingMandate,
  createFayManifest,
  classifyFayManifestPhase,
} from '@ifay/sdk';

const seed = randomBytes(32);
const humanPrime = deriveEntityKeypair(seed, 'hid', 0).value;
const myIfay = deriveEntityKeypair(seed, 'ifay', 0).value;

const manifest = createFayManifest({
  name: 'desktop-assistant-ifay',
  description: 'Local Host assistant bound to a Human Prime',
  vendor: 'Example Labs',
  fayId: myIfay.entityId,
  controlMode: 'ego',
  modules: ['device_driver_hub', 'sensor'],
  protocols: ['cap_protocol', 'dtp_protocol'],
  ego: { modelSource: '@ego-models/personal-v1' },
});

console.log(classifyFayManifestPhase(manifest)); // { phase: 'Phase 2', ... }

const mandate = createFayingMandate(
  {
    mandateId: 'mnd_01',
    humanPrimeId: humanPrime.entityId,
    fayId: myIfay.entityId,
    grade: 'G2',
    scope: {
      resources: ['res_host_window'],
      actions: ['read', 'execute'],
      domains: ['https://api.example.com'],
      terminals: ['terminal:desktop:main'],
    },
    issuedAtEpochMs: Date.now(),
    expiresAtEpochMs: Date.now() + 3600_000,
  },
  humanPrime,
);

console.log(verifyFayingMandate(mandate, { trustedIssuerPublicKeyHex: humanPrime.publicKeyHex }));
```

## Interactive Walkthrough CLI (`ifay-demo`)

```bash
# Human-readable 4-step cryptographic walkthrough (< 1 second)
npx ifay-demo

# Machine-readable JSON output
npx ifay-demo --json
```

## Running Tests

```bash
npm run build --workspace=@ifay/sdk
node --test packages/ifay-sdk/tests/*.test.mjs
```
