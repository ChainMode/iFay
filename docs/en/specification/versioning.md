# Versioning and Edition Freeze Discipline

Across the open iFay specification ecosystem, version identifiers are part of the **wire-level interoperability contract** rather than mere editorial labels. This document defines how protocol wire versions, immutable specification edition directories, and software/manifest versions relate to one another, anchored on the `Faying Protocol/1.0` versioning baseline.

---

## 1. Three Orthogonal Specification Version Axes

Every iFay protocol specification (`Faying Protocol`, `CAP`, `DTP`, `SSP`, `ICP`, `Telepathy Protocol`) tracks evolution across **three independent axes** that MUST NOT be conflated into a single identifier:

| Version Axis | Question Answered | Format | Where Recorded | Example |
|--------------|-------------------|--------|----------------|---------|
| **1. Protocol Version** | Can two independent implementations interoperate on the wire? | Two-segment `MAJOR.MINOR` | Wire envelope `version` / `protocol_version`, skill descriptors, schema identifiers | `1.0`, `Faying Protocol/1.0` |
| **2. Lifecycle Status** | Is this specification a draft or a finalized standard? | Enumeration | Document front matter `status` | `Draft` / `Final` / `Deprecated` / `Obsolete` |
| **3. Edition Freeze** | Which editorial text snapshot or errata revision is referenced? | Date `YYYY-MM-DD` | Frozen directory `docs/<lang>/specification/<YYYY-MM-DD>/`, front matter `date` | `2025-10-25` |

> **Wire Isolation Rule**: **Only the two-segment `MAJOR.MINOR` protocol version enters the wire format**. Document lifecycle status (`Draft`/`Final`) and editorial edition dates (such as `2025-10-25`) are governance metadata—they MUST NOT appear in wire envelopes, and no implementation may alter packet validation or authorization logic based on a peer's editorial edition date.

---

## 2. Two-Segment `MAJOR.MINOR` Protocol Versioning

All communication and control protocols in the iFay ecosystem use a **two-segment `MAJOR.MINOR` version with no `PATCH` segment**. Wire-level interoperability distinguishes strictly between breaking changes and backward-compatible additions:

### 2.1 `MAJOR` (Breaking Wire or Security Semantics Change)
`MAJOR` MUST be incremented and `MINOR` reset to `0` (for example, `1.2 → 2.0`) whenever a change would cause a strict implementation of the prior version to **reject valid messages, misinterpret field semantics, or violate safety invariants**:
- Changing required field types, removing existing message types, or redefining diagnostic error semantics;
- Modifying cryptographic domain-separation strings, RFC 8785 JCS canonicalization inputs, or signature verification rules;
- Altering monotonic authorization state-machine boundaries (such as `G0` emergency takeover preemption in `Faying Protocol` or `D-1..D-7` default-deny rules in `CAP`).

**Cross-`MAJOR` Rule**: Different `MAJOR` versions carry **no interoperability guarantee**. When peers share no common `MAJOR` version, they MUST fail closed with an explicit protocol mismatch error (such as `1099 E_PROTOCOL`), and MUST NOT attempt silent downgrade or best-effort parsing.

### 2.2 `MINOR` (Same-`MAJOR` Compatible Addition)
`MINOR` is incremented (for example, `1.0 → 1.1`) when introducing optional capabilities that older same-`MAJOR` peers can safely ignore:
- Adding **optional fields** to wire envelopes, capability manifests, or `SSP` `SkillDescriptor` payloads;
- Adding optional extension capabilities, default parameter budgets, or non-breaking error codes.

**Same-`MAJOR` Forward and Backward Compatibility Rules**:
1. **Higher `MINOR` serves lower `MINOR`**: A `1.1` implementation MUST interoperate cleanly with `1.0` peers down to `MAJOR.0`.
2. **Lower `MINOR` ignores unknown optional fields**: When a `1.0` decoder receives a well-formed `1.x` (`x >= 1`) message or signed descriptor with `MAJOR === 1` and valid required fields/signatures, it **MUST ignore unrecognized optional fields** rather than rejecting the payload.
3. **Rolling upgrades preserve in-flight Mandates**: Negotiating a newer `MINOR` version within the same `MAJOR` family MUST NOT invalidate unexpired, unrevoked Human Prime Mandates prior to their expiration timestamp.

### 2.3 Three-Step Implementer Checklist
When evaluating a Specification Enhancement Proposal (SEP):
1. Could a strict `1.0` peer reject or misinterpret the new message? → **Yes: bump `MAJOR` (`2.0`)**.
2. Compatible with `1.0` peers, but introduces new wire-visible optional fields or schema entries? → **Yes: bump `MINOR` (`1.1`)**.
3. Purely editorial (fixing typos, clarifying prose, adding examples, repairing links) with zero wire impact? → **Keep `MAJOR.MINOR` unchanged and publish a new dated Edition Freeze**.

---

## 3. Edition Freeze Discipline

To ensure external implementers and conformance auditors can cite permanent, reproducible specification snapshots, `specification/` directories follow strict directory-level immutability:

1. **Active Draft Workspace (`specification/draft/`)**: Evolving proposals and pre-final chapters live under `draft/`. Draft specifications carry no wire stability guarantee until promoted to `Final`.
2. **Immutable Dated Editions (e.g., `specification/2025-10-25/`)**:
   - `2025-10-25` marks the initial public `Final` release edition of the iFay `1.0` protocol suite;
   - Once frozen under a release Git tag, a dated edition directory—together with its accompanying schemas and `vectors/` conformance fixtures—is **immutable**;
   - Subsequent non-normative errata or prose clarifications are published under a new `YYYY-MM-DD/` edition directory while keeping the protocol version at `1.0`, recorded as `Editorial` in the changelog.
3. **No Disguised Normative Changes**: Any change affecting wire encoding, cryptographic signing inputs, or state-machine transitions is normative and MUST increment `MINOR` or `MAJOR` through the SEP process; it MUST NEVER be shipped silently as a dated editorial errata snapshot.

---

## 4. Protocol `MAJOR.MINOR` vs. Manifest and Package SemVer

Implementers should distinguish **protocol wire versions** from **declarative manifest and software package versions**:

| Artifact Category | Version Format | Example | Governing Rule |
|-------------------|----------------|---------|----------------|
| **Protocol Wire Envelopes & Descriptors** (`Faying`, `CAP`, `DTP`, `SSP`, `ICP`, `TP`) | Two-segment `MAJOR.MINOR` | `"1.0"` | Governed by Section 2 above; no `PATCH` segment on the wire |
| **`FayManifest` Instance & Dependency Constraints** | SemVer 2.0.0 (`MAJOR.MINOR.PATCH` and ranges) | `"version": "0.1.0"`, `"^1.0.0"` | Tracks releases of specific iFay assemblies and driver packages; `protocols[].version` accepts `"^1.0"` or `"1.0"` |
| **`Ego` Model Packages & Official Tooling** (`@ifay/sdk`, `@ifay/ifacts`) | SemVer 2.0.0 (`MAJOR.MINOR.PATCH`) | `0.1.0`, `1.0.0` | The third `PATCH` segment covers bug fixes and internal improvements that preserve public APIs and wire formats |
| **iFACTS Machine-Readable Report Format** | `<format>/<MAJOR.MINOR>` | `"ifacts-report/1.0"` | Identifies structural compatibility of certification JSON reports |

---

## Further Reading

- [Ecosystem Roadmap and Engineering Milestones](../development/roadmap.md)
- [Blueprint 13: FayManifest Declarative Assembly](../blueprint/13-FayManifest.md)
- [Blueprint 14: iFACTS Conformance Verification](../blueprint/14-iFACTS.md)
- [SEP Guidelines](../community/2-SEP-Guidelines.md)
- [Online Documentation (English)](https://ifay.ai/en/docs/specification/versioning)
