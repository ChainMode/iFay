# `@ifay/ifacts`

Runnable zero-dependency **iFACTS** (*iFay Architecture Conformance Test Suite*) progressive L1–L3 harness, `iFay Ready` tier classifier, and `ifacts-report/1.0` JSON report generator.

## Architecture & Guarantees

1. **Strictly Progressive Level Gate (`L1 -> L2 -> L3`)**:
   - **L1 (Single-Component Conformance)**: Validates `FayManifest` fixtures and target declarations against `schema/faymanifest/faymanifest.schema.json`, `FayID` RFC 4648 Base32 / HKDF-SHA256 / Ed25519 invariants, and `Ego` two-tier signed `manifest.json` + scalar-only `fidelity_report` privacy hygiene.
   - **L2 (Protocol Interface Conformance)**: Verifies cross-protocol conformance against frozen `CAP 1.0` (`D-1..D-7`), `DTP 1.0` (RFC 8785 JCS + AES-256-GCM wire frames), `FayID 1.0` (subkeys, blind `gmcref_`, single-parent hierarchy), and `SSP 1.0` (Detached Ed25519 JWS `SkillProof`) vectors. Automatically loads sibling repository vectors when present and falls back to self-contained fixtures in standalone clones.
   - **L3 (End-to-End Lifecycle Conformance)**: Executes an end-to-end Phase 1/2 lifecycle (`Human Prime` -> `iFay` FayID -> Faying Mandate -> `FayManifest` assembly -> CAP safety gate & `G0` takeover -> DTP AES-256-GCM telemetry frame -> signed `Ego` mount -> SHA-256 hash-chained audit trail).
   - **No Level Skipping**: If any `L1` check fails, `L2` and `L3` are immediately skipped with `status: "blocked_by_previous_level"`. If `L2` fails, `L3` is skipped with `status: "blocked_by_previous_level"`.
2. **Explicit `coFay` Boundary Enforcement**:
   - `Fay = iFay + coFay`. `coFay` conformance belongs exclusively to **coFACTS**. Supplying a `cofay_...` subject or manifest immediately returns `COFAY_OUT_OF_SCOPE_USE_COFACTS` (CLI exit code `2`).
3. **`iFay Ready` Application Certification Tiers**:
   - Evaluates `None`, `Bronze` (First-person Tracer + Simulated Operation), `Silver` (CAP + DTP + Credential Delegation, verified by L1 + L2), and `Gold` (SSP + full C/F/S integration, verified by L1 + L2 + L3).

## CLI Usage

```bash
# Run progressive L1 -> L2 -> L3 self-test
node packages/ifacts-harness/bin/ifacts.mjs --self-test

# Emit machine-readable ifacts-report/1.0 JSON for a custom FayManifest
node packages/ifacts-harness/bin/ifacts.mjs \
  --manifest schema/faymanifest/examples/drone-controller.faymanifest.json \
  --json
```
