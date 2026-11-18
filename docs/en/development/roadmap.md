# iFay Ecosystem Roadmap and Engineering Milestones

This document consolidates the **five-phase architectural roadmap** and **phased engineering delivery waves** of the open iFay specification ecosystem. It provides protocol implementers, Host device/application vendors, and developers with a clear view of module readiness, conformance gates, and upcoming work. For the conceptual blueprint narrative behind the five phases, see Chapter 04 of the Blueprint: [Roadmap: 5 Phases](../blueprint/04-Roadmap.md).

> **Ecosystem Scope**: `Fay = iFay + coFay`. An **iFay** (Individual Fay) replicates the intent, preferences, and capability boundaries of a specific natural person (**Human Prime**), and its conformance is verified by **iFACTS**. A **coFay** (Collective Fay) represents an organization or collective public role, and its governance and conformance are verified by the separate **coFACTS** suite.

---

## 1. Five-Phase Architectural Evolution

iFay follows a **Progressive Adoption** model: each phase builds incrementally atop the identity, mandate, and safety foundations of earlier phases, preserving backward compatibility for validly issued mandates and manifests.

| Phase | Phase Name | Core Interaction Paradigm | Key Protocols & Core Modules | Capability Boundary |
|-------|------------|---------------------------|------------------------------|---------------------|
| **Phase 1** | **Simulating Human Operations** | Visual/auditory perception and simulated UI operations over existing software | `FayID`, `Faying Protocol/1.0`, Credentials Management, First-person Tracer, Simulated Operation, `Ego` micro-model | Operates legacy software without vendor redesign while holding delegated Human Prime credentials under auditable bounds |
| **Phase 2** | **Direct Client Takeover** | Direct intent-to-Host driver invocation and encrypted bidirectional data tunnels | Adds `CAP 1.0` (Control Authority Protocol), `DTP 1.0` (Data Tunnel Protocol), `ICP 1.0` (Interactive Content Protocol), Device Driver Hub, Sensor, Personal Data Heap | Bypasses rigid visual UIs via deterministic capability safety gates, safe-state directives, and authenticated data channels |
| **Phase 3** | **Virtual World (C/F/S Architecture)** | Software ecosystem structured around Client – iFay – Server collaboration | Adds `SSP 1.0` (Skill Sharing Protocol), `Telepathy Protocol/1.0`, Registered Skill, Aligned Consciousness | Servers publish cryptographically signed skill descriptors and structured contracts directly to authorized iFay instances |
| **Phase 4** | **Full Personification (`iFay + coFay`)** | Multi-entity social collaboration across individual and collective Fays | Social Relationships & Social Permissions, Self-Awareness, Self-Driven Behavior, Internal Skill, Guardianship & Continuity, `coFay` collaboration | Smooth progression across `command`, `ego`, and high-trust `autonomous` control modes |
| **Phase 5** | **Labor and Value Distribution Transformation** | Replacing speculative attention extraction with verifiable social contribution accounting | **GMChain** and **MeriToken** (`μ` / `Merit Unit`) ecosystem integration | Records verified social contributions to anchor civic and governance voice |

### Qualitative Stance on Phase 5 GMChain and MeriToken

To keep architectural planning aligned with ecosystem governance, Phase 5 adheres strictly to the following qualitative boundaries (authoritative mechanics and quantitative parameters are defined in the `Global-Merit-Chain` specification):

1. **Strictly Non-Monetary Nature**: **GMChain** is not a financial market. **MeriToken** (measured in `μ` / `Merit Unit`) is a non-monetary social contribution measure—non-redeemable for fiat currency, non-transferable, with no cash-out exit and no speculative secondary market.
2. **Decaying Cold-Start Bootstrap**: To address initial cold-start voice for new participants, the ecosystem permits only a **strictly one-way, hard-capped** purchase of initial reputation credit. Like all reputation on GMChain, this initial allocation decays over time and collapses toward a baseline floor without sustained real social contribution—wealth cannot purchase enduring governance power.

---

## 2. Engineering Delivery Waves (Wave 0 – Wave 3)

Focused on operationalizing Phase 1 and Phase 2 while freezing Phase 3 interoperability contracts, the iFay engineering roadmap progresses across four waves:

### Wave 0: Governance Baseline, Terminology Discipline, and Freeze Readiness
- **Authoritative Terminology & Ownership**: Established strict separation between the **Human Prime** (the natural person replicated by an iFay) and the **Host** (terminal hardware devices or software applications inhabited via protocols), along with single-source-of-truth repository ownership across subprojects.
- **Protocol Versioning & Edition Discipline**: Aligned on `Faying Protocol/1.0` (`2025-10-25` edition) as the ecosystem versioning baseline—using two-segment `MAJOR.MINOR` versions on the wire and date-stamped immutable edition directories for normative specifications (see [Versioning and Edition Freeze Discipline](../specification/versioning.md)).

### Wave 1: Core Protocol Freeze and `FayManifest` Assembly Standard
- **Identity & Pairing Foundation**: Finalized `FayID` (canonical RFC 4648 lowercase no-pad Base32 identifiers, HKDF-SHA256 domain-separated subkey derivation, unlinkable `gmcref_` blind references, and single-parent hierarchy constraints) and `Faying Protocol/1.0` (`G0`–`G4` authorization grades, monotonic delegation convergence, and `G0` emergency takeover preemption) with cross-implementation test vectors.
- **Client & Interaction Protocol Suite**: Finalized `CAP 1.0` (including the `D-1..D-7` safety invariants: unknown operations default to `critical` + `DENY`, `G0` safe-state directives, and parameter-bound Human Prime confirmation for irreversible consequences), `DTP 1.0` (RFC 8785 JCS frame headers + AES-256-GCM encrypted payloads), `ICP 1.0` (`.ctx` structured interactive blocks with explicit side-effect consent), and `Telepathy Protocol/1.0`.
- **Declarative Assembly (`FayManifest`)**: Published the authoritative JSON Schema and validated reference fixtures under `schema/faymanifest/`, supporting minimal business-module declarations with automatic completion of the 7 core infrastructure modules and default `ego_model`.

### Wave 2: Signed Local Personality Vault (`Ego`) and Live Vertical Slice (`FayGer`)
- **Two-Tier Signed `Ego` Model Packages**: Delivered offline-first personality alignment package verification—signing `manifest.json` via RFC 8785 JCS + domain-separated `ifay.ego.package-signing.v1` Ed25519 keys over per-shard SHA-256 digests, while enforcing strict privacy hygiene so `fidelity_report` contains only scalar metrics and zero raw Human Prime text.
- **Runnable Phase 1/2 Vertical Slice (`FayGer`)**: Integrated deterministic `FayID` derivation, `Faying` mandate issuance, signed `Ego` mounting, `CAP` command gating, `DTP` encrypted transport, and tamper-evident SHA-256 hash-chained audit logging end to end.

### Wave 3: Official Developer SDK (`@ifay/sdk`) and Conformance Suite (`@ifay/ifacts`)
- **Zero-Dependency Official SDK (`packages/ifay-sdk`, `@ifay/sdk` v0.1.0)**: Shipped a pure Node.js standard-library SDK in the umbrella repository covering `FayID` parsing and subkey derivation, `Faying 1.0` mandate construction/verification, `FayManifest` building and phase classification, the `CAP 1.0` `D-1..D-7` client safety evaluator, `SSP 1.0` Detached Ed25519 JWS (`SkillProof`) signing/verification, and `Ego` Vault manifest verification.
- **Runnable Conformance Harness (`packages/ifacts-harness`, `@ifay/ifacts` v0.1.0)**:
  - Enforces a strictly progressive **L1 (Single-Component) → L2 (Cross-Protocol Interface Vectors) → L3 (End-to-End Lifecycle & Audit Chain)** gate: if any check at an earlier level fails, higher levels are skipped with `status: "blocked_by_previous_level"`;
  - Enforces the `iFACTS` vs. `coFACTS` scope boundary by rejecting `cofay_` subjects with `COFAY_OUT_OF_SCOPE_USE_COFACTS`;
  - Emits machine-readable `ifacts-report/1.0` JSON reports and evaluates Host application **iFay Ready** tiers (`None` / `Bronze` / `Silver` / `Gold`), while honestly reporting L4 long-horizon behavioral drift benchmarks as `deferred_phase_4_behavioral`.

---

## 3. Next Horizon

1. **Polyglot SDK Parity**: Extend language bindings to Python and Rust against the frozen `vectors/` suites and `@ifay/sdk` reference behavior to guarantee byte-identical JCS canonicalization and signature interoperability.
2. **Host Ecosystem Adoption & iFay Ready Certification**: Enable desktop, mobile, and IoT Host applications to integrate `CAP 1.0`, `DTP 1.0`, and `SSP 1.0`, self-certifying against Bronze, Silver, and Gold tiers via the `ifacts` CLI.
3. **Phase 4 Behavioral Conformance Research (iFACTS L4)**: Advance SEP (Specification Enhancement Proposal) design work on long-horizon offline personality stability, multimodal boundary benchmarks, and `iFay`–`coFay` coordination interfaces.

---

## Further Reading

- [Blueprint 04: Roadmap (5 Phases)](../blueprint/04-Roadmap.md)
- [Blueprint 13: FayManifest Declarative Assembly](../blueprint/13-FayManifest.md)
- [Blueprint 14: iFACTS Conformance Verification](../blueprint/14-iFACTS.md)
- [Specification: Versioning and Edition Freeze Discipline](../specification/versioning.md)
- [Tutorial: Build and Verify a Local iFay Client Node in 15 Minutes](../tutorials/building-a-client-node.md)
- [Online Documentation (English)](https://ifay.ai/en/docs/iFay/development/roadmap)
