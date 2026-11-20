# `@ifay/soul` — Portable Digital Soul, Peer Sync Ledger & Adaptive `BuF` Slicer

Zero-third-party-dependency official Node.js (`>= 20.0.0`) package and `ifay-soul` CLI for building, peer-syncing, and adaptively slicing **iFay Digital Soul** Primary Bodies and accountable **coFay** public role seats into standards-compliant `BUF\0` v1 binaries that load natively in **FayGer** (`fayger inspect` / `fayger run`).

---

## Core Capabilities

1. **6-Dimension `iFay Profile` (`ifay-profile/1.0`) vs `Ego`**:
   - **Identity**: Canonical `FayID` (`ifay_...` bound to Human Prime `hid_...`), **stealth by default** (`visibility_mode: "stealth"`), with opt-in Ed25519-signed **Platform Registration Attestations** (`real_name`, `expert`, `commerce`, `service`, `social`).
   - **Active `Ego` Reference**: Supports multiple named personas (`professional`, `casual`, domain-specific modes) while enforcing the **strict single-active-Ego invariant** (exact count `1` active at any moment), plus `Ego School` Human Prime correction logs.
   - **Thought**: Structured across all four blueprint subtypes (`content`, `data`, `knowledge_base`, `info_feed`), including an AES-256-GCM **DTP 1.0** encrypted personal context ingestion hook (`ingestDtpContextFrame`).
   - **Skill**: Registered action capabilities across all six blueprint types (`api`, `workflow`, `bot`, `agent`, `app`, `microservice`).
   - **Hardware**: Terminal `device`, `storage`, and `computing` descriptors.
   - **Permissions**: `inherent`, `persistent`, and `ephemeral` lifecycles with extensible `auth_methods`.
2. **Primary Body & Peer-to-Peer Replica Sync (`PrimaryBodyStore` + `syncPrimaryReplicas`)**:
   - Terminal embodiments commit signed delta events (`thought_added`, `dtp_context_ingested`, `skill_registered`, `human_correction`, `ego_switched`, `platform_registered`) back to a Primary Body.
   - Multiple peer Primary Body replicas (for example, local NVMe folder + NAS / cloud-synced directory) reconcile deterministically via an Ed25519-signed, SHA-256 causal Merkle-DAG log with tamper detection (`LEDGER_HASH_MISMATCH`, `LEDGER_SIGNATURE_INVALID`, `LEDGER_GENESIS_MISMATCH`).
3. **Adaptive Embodiment Slicing (`sliceSoulForDevice`) & Byte-Exact `BuF` v1 Codec (`packBufBinary` / `parseBufBinary`)**:
   - Negotiates capabilities (`requested ∩ granted_capabilities`) and slices `.buf` embodiments against a FayGer `DeviceRuntimeProfile` (`fayger-device-profile/1.0`):
     - **`super` / `plus` workstation**: Full `Thought`, `Skill`, multi-persona `Ego` pod, and `Ego School` alignment buffer.
     - **`normal` / `lite` edge / drone / mobile**: Domain-filtered `Thought` and capability-matched `Skill` subsets + compact distilled LoRA `Ego` slice.
     - **`thin` / `remote_only: true` terminal**: Zero heavy local `Thought` or `Ego` weights; bundles an Ed25519-signed `RemotePrimaryPointer` (`ifay-remote-pointer/1.0`) back to the Primary Body.
   - Emits deterministic RFC 8949 canonical CBOR manifests, section indexes, section SHA-256 digests, `manifest_digest`, Ed25519 `seal_and_sign` signatures, and IEEE CRC-32 trailers matching Rust `fayger-buf` / `fayger-loader` bit-for-bit.
4. **Accountable `coFay` Seat Builder (`CofaySeatBuilder`)**:
   - Replaces personal `Ego` with signed public `RoleCharter 1.0` documents across `org_service`, `functional_post`, and `project_collaborator`, enforcing personal-Ego prohibition (`COFAY_EGO_FORBIDDEN`), natural-person steward rotation, and dual-signed atomic ownership transfer (`TransferEnvelope 1.0`).

---

## CLI Quickstart (`ifay-soul`)

```bash
# 1. Initialize a 6-dimension iFay Digital Soul Primary Body
npx ifay-soul init ./my-soul --name "Alex Digital Soul"

# 2. Record a Thought item & a Human Prime alignment correction
npx ifay-soul add-thought ./my-soul --subtype knowledge_base --title "Flight Rules" --text "Keep RTH >= 50m" --domain aerial_photography
npx ifay-soul record-correction ./my-soul --prompt "Draft update" --wrong "6 paragraphs" --corrected "3 bullets" --rule "Max 3 bullets"

# 3. Sync deterministically with a peer Primary Body replica (e.g., NAS / cloud folder)
npx ifay-soul sync ./my-soul ./my-soul-nas-replica

# 4. Slice a compact .buf embodiment for a constrained edge/drone FayGer runtime
npx ifay-soul slice ./my-soul --tier lite --out ./dist/my-ifay-lite.buf
npx ifay-soul inspect-buf ./dist/my-ifay-lite.buf

# 5. Initialize an accountable coFay project_collaborator seat package
npx ifay-soul init-cofay ./oss-seat --archetype project_collaborator

# 6. Run the full sub-second cryptographic walkthrough
npm run soul:demo
```

---

## Programmatic Usage

```js
import {
  OFFICIAL_DEVICE_PROFILES,
  PrimaryBodyStore,
  sliceSoulForDevice,
  syncPrimaryReplicas,
} from '@ifay/soul';

const homePrimary = PrimaryBodyStore.init({ displayName: 'Alex Soul' });
const cloudReplica = PrimaryBodyStore.createPeerReplica(homePrimary, {
  replicaId: 'replica:cloud-drive',
});

homePrimary.addThought({
  subtype: 'knowledge_base',
  title: 'Coastal Survey Checklist',
  text: 'Check ND16 filter and wind telemetry.',
  domain: 'aerial_photography',
});

const sync = syncPrimaryReplicas(homePrimary, cloudReplica);
console.log('Replicas consistent:', sync.consistent, sync.stateRootSha256);

const liteSlice = sliceSoulForDevice(homePrimary, OFFICIAL_DEVICE_PROFILES.lite);
console.log('Lite .buf bytes:', liteSlice.bufBytes.length, liteSlice.mode);
```

---

## Related Specifications

- [Blueprint 07: iFay Profile](../../docs/en/blueprint/07-iFay-Profile.md) ([中文](../../docs/zh-CN/blueprint/07-iFay画像.md))
- [Blueprint 13: Declarative Assembly (`FayManifest`)](../../docs/en/blueprint/13-FayManifest.md) ([中文](../../docs/zh-CN/blueprint/13-FayManifest声明式组装.md))
- [`@ifay/sdk`](../ifay-sdk/README.md) · [`@ifay/ifacts`](../ifacts-harness/README.md) · [License (MIT)](../../LICENSE)
