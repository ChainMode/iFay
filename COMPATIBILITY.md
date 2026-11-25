# iFay Ecosystem Compatibility & Maturity Matrix (`2026-11-25`)

This document is the single source of truth across the **13 public `ChainMode` repositories** (plus the official `ifay.ai` and `Meritora` web documentation properties) for:
1. **Normative Specification / Wire Version** vs. **Reference Kit GitHub Release Tag**;
2. **Distribution Channel Status** (prebuilt GitHub Release binaries vs. source/GitHub Release workspace packages);
3. **Engineering Honesty Boundaries** (what runs end-to-end offline today vs. what is experimental, local-devnet-scoped, or awaiting maintainer external credentials).

---

## 1. Cross-Repository Version & Distribution Matrix

| Repository | Normative Spec / Wire Version | Latest GitHub Release | Package / Binary Distribution Today | Primary Verification Command |
| --- | --- | --- | --- | --- |
| [`ChainMode/iFay`](https://github.com/ChainMode/iFay) | `FayManifest 1.0` · `ifacts-report/1.0` · `BUF\0 v1` | `v0.3.0` | GitHub Release / Source Workspace (`@ifay/sdk`, `@ifay/soul`, `@ifay/ifacts`, `@ifay/mcp-server` `0.1.0`; npm publish pending) | `npm test && npm run demo` |
| [`ChainMode/FayGer`](https://github.com/ChainMode/FayGer) | `Runtime_Interface 1.0` · `FHBP/1.0` | `v0.3.1` | **Prebuilt GitHub Release Assets**: 5 OS/arch CLI+Daemon binaries, `FayGer-macos-arm64.dmg`, `fayger-mobile-guardian-android.apk`, ISO C99 Firmware SDK | `fayger doctor && fayger self-test` |
| [`ChainMode/Ego`](https://github.com/ChainMode/Ego) | `Ego_Package 1.0` (`.egopod` + Two-Tier Vault) | `v0.3.0` | GitHub Release / Source Python Package (`ego-pod 0.3.0`; PyPI publish pending) | `pytest` (inside `release/dev`) |
| [`ChainMode/FayID`](https://github.com/ChainMode/FayID) | `FayID 1.0` (`2025-10-25`) | `v1.1.0` | GitHub Release / Source Node ESM (`@ifay/fayid 1.1.0`) | `npm test && npm run demo` |
| [`ChainMode/Faying-Protocol`](https://github.com/ChainMode/Faying-Protocol) | `Faying 1.0` & `1.1-cofay` | `v1.2.0` | GitHub Release / Source Node ESM + Rust + Python (`@ifay/faying-protocol 1.2.0`) | `npm test && npm run demo` |
| [`ChainMode/Control-Authority-Protocol`](https://github.com/ChainMode/Control-Authority-Protocol) | `cap/1.0` (`D-1..D-7`) | `v1.0.0` | GitHub Release / Source TypeScript & Rust Reference Engines | `npm test` & `cargo test` |
| [`ChainMode/Data-Tunnel-Protocol`](https://github.com/ChainMode/Data-Tunnel-Protocol) | `dtp/1.0` (RFC 8785 JCS + AES-256-GCM) | `v1.1.0` | GitHub Release / Source TS (`data-tunnel-protocol 1.1.0`, `npm` & `pnpm` supported) + Rust (`dtp-ref`) | `npm test && npm run demo` |
| [`ChainMode/Skill-Sharing-Protocol`](https://github.com/ChainMode/Skill-Sharing-Protocol) | `ssp/1.0` (`2025-10-25`, Detached Ed25519 JWS) | `v1.1.0` | GitHub Release / Source TS (`skill-sharing-protocol 1.1.0`, `ssp-publisher` & `ssp-radar`) | `npm test && npm run demo` |
| [`ChainMode/Interactive-Conversation-Protocol`](https://github.com/ChainMode/Interactive-Conversation-Protocol) | `icp-ctx-file/1.0` (`2025-10-25`) | `v1.1.0` | GitHub Release / Source Node ESM (`@ifay/icp 1.1.0`) | `npm test && npm run demo` |
| [`ChainMode/Telepathy-Protocol`](https://github.com/ChainMode/Telepathy-Protocol) | `TP/1.0` | `v1.1.0` | GitHub Release / Source Node ESM (`@ifay/tp-sdk 1.1.0`) | `npm test && npm run demo` |
| [`ChainMode/coFay`](https://github.com/ChainMode/coFay) | `RoleCharter 1.0` · `coFACTS L1` | `v1.1.0` | GitHub Release / Source Node ESM (`@ifay/cofay 1.1.0`) | `npm test && npm run demo` |
| [`ChainMode/Global-Merit-Chain`](https://github.com/ChainMode/Global-Merit-Chain) | `GMChain` Constitutional Ledger (`i128` Fixed-Point) | `v0.3.0` | GitHub Release / Source Rust Workspace (`gmc-core`, `gmc-identity`, `gmc-node`) | `cargo test --workspace` |
| [`ChainMode/MeriToken`](https://github.com/ChainMode/MeriToken) | `MeriToken` Charter (`μ` / Merit Unit) | `v0.2.0` | 9-Locale Specification & Governance Blueprint (enforced in `GMChain`) | `docs-ci` link & parity gate |

---

## 2. Explicit Real-Today vs. Preview / Boundary Disclosures

To prevent misinterpretation by evaluators, contributors, and hardware integrators, the iFay project enforces the following transparency boundaries:

1. **Registry Packages (`npm` / `PyPI`)**:
   - `@ifay/*` Node packages and `ego-pod` Python packages pass `npm pack --dry-run` / `twine check` locally and ship in GitHub Releases, but are **not yet published to the public npmjs.com or pypi.org registries**. Always clone the repository or use the prebuilt `FayGer` installer (`scripts/install.sh` / `scripts/install.ps1`) rather than running `npm install @ifay/sdk` or `pip install ego-pod` from public registries until registry publication is announced.
2. **`FayGer` Desktop, Mobile & Signing Status (`v0.3.1`)**:
   - **CLI + Daemon + Web Dashboard (`install.sh` / `install.ps1`)**: Prebuilt for 5 OS/arch targets with SHA-256 verification; runs directly without macOS Gatekeeper quarantine prompts.
   - **macOS `.dmg` (`FayGer-macos-arm64.dmg`)**: Currently **ad-hoc signed** until maintainer Apple `Developer ID` notarization secrets are configured in CI. Browser downloads of the `.dmg` require macOS `Right-Click -> Open` or `System Settings -> Privacy & Security -> Open Anyway` on first launch.
   - **Mobile Guardian (`Android .apk` & `iOS TestFlight Kit`)**: `http://<LAN-IP>:7979/mobile` works immediately in any mobile browser on the same LAN/Tailscale network; `fayger-mobile-guardian-android.apk` (`~17 KB` zero-AndroidX pure Android SDK `WebView` wrapper) is debug-signed for direct sideloading; `release/mobile/ios-testflight/` provides the Xcode/TestFlight engineering kit (Apple's platform cap is 10,000 external testers once an Apple Developer Team ID is configured; **no public TestFlight invite link is active yet**).
3. **`Ego` Stub Default vs. Real Neural LoRA Weights (`v0.3.0`)**:
   - By default, `ego demo` and CI tests use a deterministic zero-download `StubBackend` (`< 2s`, zero GPU/network) to verify PII scrubbing, corpus compilation, RFC 8785 JCS + Ed25519 two-tier `.egopod` signing, and `FayGer` handoff.
   - Real neural LoRA fine-tuning (`--backend peft` / `--backend mlx`) is implemented and maintainer-verified offline on `Qwen/Qwen2.5-0.5B-Instruct` (see [`ChainMode/Ego/release/dev/REAL_TRAINING.md`](https://github.com/ChainMode/Ego/blob/main/release/dev/REAL_TRAINING.md)).
4. **`Telepathy Protocol` (`TP/1.0`) Normative Core vs. Latent Track**:
   - `TP/1.0` conformance covers **explicit JSON schema cognitive frames, ontology negotiation, LWW `SharedContext`, and mandatory natural-language fallback**. Cross-model raw hidden-state transfer is **not** claimed; `ExperimentalLatentFrame` is strictly opt-in and rejected unless both Fays prove identical base-model and adapter SHA-256 digests (`TP-LAT002`).
5. **`Global-Merit-Chain` (`GMChain`) & `MeriToken` (`μ`)**:
   - `gmc-node` (`v0.3.0`) runs a deterministic local/LAN 4-validator 2-phase BFT devnet and single-node JSON-RPC bridge (`:8546`) integrated with `FayGer` and `Meritora` (`/workbench`), not a live multi-organization public mainnet.
   - `MeriToken` (`美誉值`, `μ`) is **strictly non-monetary**: `0` transaction fee, `0` block/validator reward, non-transferable, non-tradable, with monotonic `minMerit` protection and active-surplus consumption on priority exercise (`consume_priority`).
