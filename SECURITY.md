# Security Policy

## Supported Versions

Security fixes and advisories are actively maintained for `main` and the current GitHub Release baseline (`v0.3.0`) in this umbrella repository (packages are distributed from source / GitHub Releases today; public npm registry publication is tracked in [`PUBLISHING.md`](./PUBLISHING.md)):

| Component / Artifact | Version / Branch | Supported |
| --- | --- | --- |
| Umbrella Release Baseline (`ChainMode/iFay`) | `main` / `v0.3.0` | Yes |
| `@ifay/sdk` (`packages/ifay-sdk`, workspace pkg `0.1.0`) | `main` / `v0.3.0` | Yes |
| `@ifay/soul` (`packages/ifay-soul`, workspace pkg `0.1.0`) | `main` / `v0.3.0` | Yes |
| `@ifay/ifacts` (`packages/ifacts-harness`, workspace pkg `0.1.0`) | `main` / `v0.3.0` | Yes |
| `@ifay/mcp-server` (`packages/mcp-server`, workspace pkg `0.1.0`) | `main` / `v0.3.0` | Yes |
| `FayManifest` Schema (`schema/faymanifest/`) | `main` / `1.0` | Yes |
| Pre-baseline snapshots | `< v0.1.0` | No |

## Security Scope

We particularly welcome security reports covering the following areas in `iFay`:

1. **`@ifay/sdk` Cryptographic & Protocol Helpers (`packages/ifay-sdk`)**:
   - `FayID` RFC 4648 lowercase no-pad Base32 parsing, `HKDF-SHA256` purpose subkey isolation (`ifay.fayid.entity.v1`, `ifay.ego.package-signing.v1`, `ifay.gmc.natural-person.v1`), `Ed25519` Holder-of-Key signing/verification, and RFC 8785 JCS canonicalization.
   - `Faying 1.0` Mandate verification, autonomy convergence checks (`DELEGATE` non-escalation), and `G0` Human Prime emergency takeover preemption.
   - `CAP 1.0` `D-1..D-7` client safety gate evaluation (fail-closed `critical + DENY` defaults, irreversibility floor elevation, parameter-bound Human Prime confirmation, and unconditional `fund_transfer` rejection).
   - `SSP 1.0` Detached `Ed25519` JWS (`alg: "EdDSA"`) `SkillProof` verification, `DTP 1.0` `AES-256-GCM` authenticated framing, and `Ego` two-tier Vault signature verification.
2. **`@ifay/ifacts` Conformance Harness (`packages/ifacts-harness`)**:
   - Bypass of the progressive `L1 -> L2 -> L3` gate (`blocked_by_previous_level`), `coFay` / `coFACTS` scope boundary checks (`COFAY_OUT_OF_SCOPE_USE_COFACTS`), or `SHA-256` hash-chained lifecycle audit verification.
3. **`FayManifest` Authoritative Schema (`schema/faymanifest/`)**:
   - Schema validation bypasses, unsafe dependency auto-completion, or phase-classification mismatches that could grant unintended runtime privileges.

## Reporting a Vulnerability

**Please do NOT report undisclosed security vulnerabilities through public GitHub Issues, Discussions, or Pull Requests.**

- **Primary Channel (Recommended)**: Submit a report privately via **GitHub Private Vulnerability Reporting (Security Advisories)**:
  - https://github.com/ChainMode/iFay/security/advisories/new
- **Fallback Email Channel**: If GitHub Security Advisories is unavailable to you, email **[jah.g@ifay.ai](mailto:jah.g@ifay.ai)** with `[SECURITY][iFay]` in the subject line.

Please include affected file paths or package versions, minimal reproduction steps or proof-of-concept inputs, and an assessment of potential impact on a Human Prime, `iFay`, `coFay`, or Host environment.

## Coordinated Disclosure Policy

- **Acknowledgment**: Within **72 hours** of receiving your report.
- **Triage & Assessment**: Initial validation, severity classification, and remediation plan within **7 calendar days**.
- **Coordinated Disclosure Window**: Up to **90 days** from report submission to develop, verify, and publish a fix before public disclosure (mutually adjustable if complex cross-protocol coordination is required).
- **Credit**: We gladly credit security researchers in published advisories unless anonymity is requested.
