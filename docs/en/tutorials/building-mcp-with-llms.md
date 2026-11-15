# Guide: Bridging MCP and LLM Tools Safely into the iFay Protocol Stack

Large Language Models (LLMs) and the Model Context Protocol (MCP) ecosystem provide rich external tool servers—from calendar scheduling to smart-device automation. However, exposing raw MCP tools directly to a general-purpose LLM agent introduces three systemic risks:

1. **Unverified Tool Provenance**: Plain JSON tool schemas carry no cryptographic publisher proof, leaving clients vulnerable to descriptor tampering or tool-poisoning attacks;
2. **Silent Irreversible Side Effects**: Free-form chat loops can trigger irreversible external actions without structured parameter disclosure or explicit Human Prime consent;
3. **Unbounded Host Execution**: Standard tool-calling pipelines lack deterministic enforcement tied to authorization grades (`G0`–`G4`) and Host safe-state preemption.

In iFay, the embedded local **Ego** micro-model works alongside external LLMs and MCP servers by enforcing a three-stage defense-in-depth pipeline—**`SSP 1.0` (Signed Skill Discovery) → `ICP 1.0` (Structured Consent) → `CAP 1.0` (Deterministic Capability Gate)**—keeping every external tool call anchored to Human Prime sovereignty.

---

## Architecture Overview

```text
[MCP Tool Server]
      │ 1. Export tool schema & sign SSP 1.0 SkillDescriptor (RFC 8785 JCS + Detached Ed25519 JWS)
      ▼
[iFay Registered Skill Layer (@ifay/sdk: verifySkillDescriptor)]
      │ 2. LLM proposes tool call; irreversible actions render an ICP 1.0 .ctx consent card
      ▼
[Human Prime] ── Reviews disclosed parameters & signs parameter-bound confirmation (confirmed_params_sha256)
      │ 3. Evaluated alongside Faying Mandate by CAP 1.0 gate (@ifay/sdk: evaluateCapAction)
      ▼
[Host Device / MCP Bridge Executor]
```

---

## Step 1: Wrap MCP Tools as Signed `SSP 1.0` `SkillDescriptor`s

Suppose you operate an existing MCP tool `calendar.reschedule_meeting`. Before registering it with an iFay node, the publisher signs the descriptor with its `FayID` keypair using `signSkillDescriptor` from `@ifay/sdk`, producing an RFC 8785 JCS + Detached Ed25519 JWS (`alg: "EdDSA"`) `SkillProof`:

```javascript
import { randomBytes } from 'node:crypto';
import {
  deriveEntityKeypair,
  signSkillDescriptor,
  verifySkillDescriptor,
} from './packages/ifay-sdk/src/index.mjs';

// Skill publisher identity (ifay_ or org_)
const providerSeed = randomBytes(32);
const skillPublisher = deriveEntityKeypair(providerSeed, 'org', 'acme-mcp-bridge').value;

// Map the MCP tool definition into an SSP 1.0 SkillDescriptor
const mcpBridgedDescriptor = {
  protocol: 'ssp/1.0',
  version: '1.0',
  skillId: 'skill.mcp.calendar.reschedule',
  name: 'MCP Calendar Rescheduler',
  description: 'Reschedules a calendar event and notifies external attendees',
  publisherFayId: skillPublisher.entityId,
  origin: 'https://mcp-bridge.acme.example',
  visibility: 'restricted',
  executionMode: 'sync',
  inputSchema: {
    type: 'object',
    required: ['eventId', 'newStartIso', 'notifyAttendees'],
    properties: {
      eventId: { type: 'string' },
      newStartIso: { type: 'string' },
      notifyAttendees: { type: 'boolean' },
    },
  },
  outputSchema: {
    type: 'object',
    required: ['updated', 'updatedAtIso'],
  },
};

// Attach Detached Ed25519 JWS SkillProof
const signedSkill = signSkillDescriptor(mcpBridgedDescriptor, {
  signer: skillPublisher,
  kid: `${skillPublisher.entityId}#ssp-1`,
  created: new Date().toISOString(),
});

// iFay verifies provenance, version compatibility, and restricted-visibility caller auth before mounting
const callerIfay = deriveEntityKeypair(randomBytes(32), 'ifay', 0).value;
const verifyResult = verifySkillDescriptor(signedSkill, {
  trustedPublicKeyHex: skillPublisher.publicKeyHex,
  consumerVersion: '1.0',
  requireAuthForRestricted: true,
  callerFayId: callerIfay.entityId,
});

console.log('SSP SkillProof verification :', verifyResult);
// { valid: true, publisherFayId: 'org_...', kid: 'org_...#ssp-1' }
```

> **Same-`MAJOR` Forward Compatibility**: Following the ecosystem's two-segment `MAJOR.MINOR` discipline, a `1.0` client calling `verifySkillDescriptor` accepts a valid `1.1` descriptor containing extra optional metadata fields (preserving them in the JCS signing input) while strictly rejecting incompatible `2.0` descriptors.

---

## Step 2: Obtain Explicit Human Prime Consent via `ICP 1.0` `.ctx` Blocks

When an LLM proposes rescheduling event `evt_9042` and emailing external attendees, dispatching external notifications carries an **irreversible consequence (`irreversible_consequence`)**. An iFay MUST NOT execute that side effect solely from unstructured LLM text output.

Using the **Interactive Content Protocol (`ICP 1.0`)** pattern, the client renders a structured `.ctx` block to the Human Prime disclosing the exact skill publisher, normalized parameters, and SHA-256 digest (`computeCapParamsSha256`) before collecting an explicit reaction:

```javascript
import { computeCapParamsSha256 } from './packages/ifay-sdk/src/index.mjs';

// Structured tool arguments proposed by the LLM
const proposedToolParams = {
  eventId: 'evt_9042',
  newStartIso: '2026-11-18T14:00:00Z',
  notifyAttendees: true,
};

// Compute deterministic RFC 8785 JCS SHA-256 digest over the exact parameters
const paramsSha256 = computeCapParamsSha256(proposedToolParams);

// Construct the ICP 1.0 .ctx interactive consent block presented to the Human Prime
const icpConsentBlock = {
  protocol: 'icp/1.0',
  blockType: 'application/vnd.ifay.ctx+json',
  cardId: 'ctx_confirm_reschedule_01',
  title: 'Confirm Meeting Reschedule & External Notification',
  disclosure: {
    skillId: signedSkill.skillId,
    publisher: signedSkill.publisherFayId,
    irreversibility: 'irreversible_consequence',
    parameters: proposedToolParams,
    paramsSha256,
  },
  reactions: [
    { id: 'approve_once', label: 'Approve Once', requiresExplicitConsent: true },
    { id: 'cancel', label: 'Cancel', requiresExplicitConsent: false },
  ],
};

console.log('ICP .ctx bound parameter digest :', icpConsentBlock.disclosure.paramsSha256);
```

If a subsequent LLM turn mutates any field in `proposedToolParams`, its recomputed JCS SHA-256 digest will no longer match `confirmed_params_sha256`, causing the `CAP 1.0` gate in Step 3 to deny execution immediately.

---

## Step 3: Gate Execution Through `CAP 1.0` (`D-1..D-7`)

Before forwarding `tools/call` to the underlying MCP transport or Host driver, invoke `evaluateCapAction` to enforce all `CAP 1.0` invariants:

1. **Irreversibility Criticality Floor (`D-6`)**: Even if an upstream LLM orchestrator passes `caller_criticality_override: 'routine'`, any operation marked `irreversible_consequence` is clamped upward to at least `high` (`escalation_clamped: true`);
2. **Parameter-Bound Human Prime Confirmation (`D-7`)**: `high`-criticality irreversible actions require a fresh, terminal-attested confirmation whose `confirmed_params_sha256` matches the exact call payload;
3. **Out-of-Scope Fund Transfer Block (`D-7c`)**: Any tool categorized as `domain_category: 'fund_transfer'` is unconditionally denied (`2007 E_OUT_OF_SCOPE_FUND_TRANSFER`).

```javascript
import {
  createFayingMandate,
  toCapMandateBinding,
  ed25519KeypairFromSeed,
  signCapDriverManifest,
  evaluateCapAction,
} from './packages/ifay-sdk/src/index.mjs';

const hpSeed = randomBytes(32);
const humanPrime = deriveEntityKeypair(hpSeed, 'hid', 0).value;
const nowMs = Date.now();

// Sign the MCP bridge capability manifest declaring irreversible_consequence
const bridgeAnchorSeed = randomBytes(32);
const bridgeAnchorKey = ed25519KeypairFromSeed(bridgeAnchorSeed);
const trustAnchors = {
  mcp_bridge_anchor: {
    algorithm: 'Ed25519',
    public_key_raw_hex: bridgeAnchorKey.publicKeyHex,
  },
};

const bridgeCapabilityManifest = signCapDriverManifest(
  {
    manifest_id: 'mf_mcp_calendar_bridge',
    driver_id: 'drv_mcp_calendar',
    version: '1.0.0',
    issued_at: new Date(nowMs).toISOString(),
    signer_key_id: 'mcp_bridge_anchor',
    resources: [
      {
        resource_id: 'res_mcp_calendar',
        safe_states: [{ safe_state_id: 'disconnect_mcp_transport', description: 'Close external MCP session' }],
        operations: [
          {
            operation_id: 'reschedule_meeting',
            mode: 'execute',
            criticality: 'sensitive',
            consequence_irreversibility: 'irreversible_consequence',
            domain_category: 'external_communication',
          },
        ],
      },
    ],
  },
  bridgeAnchorSeed,
);

const mandate = createFayingMandate(
  {
    mandateId: 'mnd_mcp_01',
    humanPrimeId: humanPrime.entityId,
    fayId: callerIfay.entityId,
    grade: 'G2',
    scope: {
      resources: ['res_mcp_calendar'],
      actions: ['execute'],
      domains: ['https://mcp-bridge.acme.example'],
      terminals: ['host:desktop:primary'],
    },
    deviceId: 'host:desktop:primary',
    issuedAtEpochMs: nowMs,
    expiresAtEpochMs: nowMs + 5 * 60 * 1000,
  },
  humanPrime,
);

// Evaluate with the parameter-bound Human Prime confirmation from Step 2
const gateDecision = evaluateCapAction(
  {
    protocol_version: '1.0',
    request_id: 'req_mcp_exec_01',
    fay_id: callerIfay.entityId,
    now_epoch_ms: nowMs + 1000,
    resource_id: 'res_mcp_calendar',
    operation_id: 'reschedule_meeting',
    requested_mode: 'execute',
    caller_criticality_override: 'routine', // Clamped back to 'high' automatically
    params: proposedToolParams,
    manifest: bridgeCapabilityManifest,
    grant: {
      grant_id: 'grt_mcp_01',
      resource_id: 'res_mcp_calendar',
      allowed_modes: ['execute'],
      min_grade: 'G2',
      mandate_binding: toCapMandateBinding(mandate, 'res_mcp_calendar'),
    },
    human_confirmation: {
      confirmation_id: 'cnf_ctx_01',
      human_prime_id: humanPrime.entityId,
      confirmed_params_sha256: paramsSha256,
      terminal_attested_disclosure: true,
      expires_at_epoch_ms: nowMs + 60 * 1000,
    },
  },
  trustAnchors,
);

console.log('CAP gate decision :', gateDecision);
// { decision: 'ALLOW', effective_criticality: 'high', effective_grade: 'G2', escalation_clamped: true }
```

Only when `gateDecision.decision === 'ALLOW'` should your adapter dispatch the JSON-RPC `tools/call` request to the MCP server.

---

## Production Hardening Checklist

Before deploying an MCP or LLM tool bridge in production, verify every item below:

- [ ] **Require `SSP 1.0` `SkillProof` on every tool**: Reject unsigned descriptors, invalid Ed25519 JWS signatures, or cross-`MAJOR` version mismatches;
- [ ] **Fail closed on hallucinated tool names**: Register only audited MCP operations in the `DriverCapabilityManifest` so unknown operations automatically resolve to `critical` + `DENY` (`D-5`);
- [ ] **Bind `ICP 1.0` `.ctx` consent to exact parameter digests**: Require `confirmed_params_sha256` verification before executing any external communication, deletion, or state-mutating tool;
- [ ] **Honor `G0` emergency takeover**: Preempt in-flight MCP sessions immediately and enter the declared `safe_state_id` whenever the Human Prime triggers `G0`.

---

## Further Reading

- [Tutorial: Build and Verify a Local iFay Client Node in 15 Minutes](./building-a-client-node.md)
- [Blueprint 09: Interaction Layer – Perception (including ICP)](../blueprint/09-Interaction-Layer-Perception.md)
- [Blueprint 10: Interaction Layer – Action (including CAP)](../blueprint/10-Interaction-Layer-Action.md)
- [Blueprint 12: Cognition Layer – Skills (including SSP)](../blueprint/12-Cognition-Layer-Skills.md)
- [Online Documentation (English)](https://ifay.ai/en/docs/tutorials/building-mcp-with-llms)
