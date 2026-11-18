import { createHash, createPublicKey } from 'node:crypto';
import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';
import {
  base32DecodeNoPad,
  base32EncodeNoPad,
  canonicalizeJcs,
  classifyFayManifestPhase,
  computeCapParamsSha256,
  evaluateCapAction,
  isSspVersionCompatible,
  parseFayId,
  resolveFayManifestDependencies,
  toCapMandateBinding,
  validateFayManifest,
  verifyEd25519,
  verifyFayingMandate,
  verifySkillDescriptor,
  type FayIdKind,
  type FayManifest,
  type FayingGrade,
  type FayingMandate,
} from '@ifay/sdk';

export const MCP_SERVER_NAME = '@ifay/mcp-server';
export const MCP_SERVER_VERSION = '0.1.0';
export const SUPPORTED_MCP_PROTOCOL_VERSIONS = ['2025-03-26', '2024-11-05'] as const;

export const JSONRPC_ERRORS = Object.freeze({
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
});

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const VALID_FAYID_KINDS = new Set<string>([
  'HUMAN_ID',
  'IFAY_ID',
  'COFAY_ID',
  'ORGANIZATION_ID',
  'DYNAMIC_CODE',
  'AUTHORIZATION_GRANT',
  'VERIFICATION_CODE',
  'OPAQUE_REF',
]);

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: unknown;
}

export interface JsonRpcSuccess {
  jsonrpc: '2.0';
  id: string | number | null;
  result: unknown;
}

export interface JsonRpcFailure {
  jsonrpc: '2.0';
  id: string | number | null;
  error: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export type JsonRpcResponse = JsonRpcSuccess | JsonRpcFailure;

class RpcParamsError extends Error {
  readonly data?: unknown;
  constructor(message: string, data?: unknown) {
    super(message);
    this.name = 'RpcParamsError';
    this.data = data;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isValidEd25519PublicKeyHex(hex: string): boolean {
  if (!/^[0-9a-f]{64}$/i.test(hex)) return false;
  try {
    const raw = Buffer.from(hex, 'hex');
    createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: 'der',
      type: 'spki',
    });
    return true;
  } catch {
    return false;
  }
}

export const MCP_TOOLS = [
  {
    name: 'fayid_validate',
    description:
      'Validate a canonical FayID identifier (ifay_, hid_, cofay_, org_, dyn_, grt_, vrf_, gmcref_) and optionally verify DID consistency, Ed25519 public-key hash binding, and Holder-of-Key challenge signatures.',
    inputSchema: {
      type: 'object',
      required: ['fayId'],
      additionalProperties: false,
      properties: {
        fayId: {
          type: 'string',
          description: 'Candidate FayID string (for example ifay_<base32> or hid_<base32>).',
        },
        expectedKind: {
          type: 'string',
          enum: Array.from(VALID_FAYID_KINDS),
          description: 'Optional expected FayID kind constraint.',
        },
        did: {
          type: 'string',
          description: 'Optional DID URI (such as did:fay:ifay_<base32>) to verify consistency.',
        },
        publicKeyHex: {
          type: 'string',
          description:
            'Optional 32-byte raw Ed25519 public key (64 hex chars) to verify SHA-256 -> Base32 entity ID derivation.',
        },
        challengeUtf8: {
          type: 'string',
          description: 'Optional UTF-8 challenge message signed by the entity private key.',
        },
        signatureHex: {
          type: 'string',
          description: 'Optional 64-byte Ed25519 signature (128 hex chars) over challengeUtf8.',
        },
      },
    },
    annotations: {
      title: 'Validate FayID & Ed25519 Key Binding',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'faymanifest_validate',
    description:
      'Validate a FayManifest JSON payload against the authoritative faymanifest.schema.json and return resolved infrastructure modules, governed package namespaces, and Phase 1-5 classification.',
    inputSchema: {
      type: 'object',
      required: ['manifest'],
      additionalProperties: false,
      properties: {
        manifest: {
          type: 'object',
          description: 'Candidate FayManifest JSON object to validate.',
        },
      },
    },
    annotations: {
      title: 'Validate FayManifest JSON Payload',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'cap_evaluate',
    description:
      'Evaluate an AI agent Host/tool action request against a Control Authority Protocol (CAP 1.0) capability policy and Faying Mandate. Returns deterministic ALLOW/DENY, D-1..D-7 rule ID, safe-state directives, and a SHA-256 audit trace.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        action: {
          type: 'object',
          description: 'Target Host/tool action to evaluate.',
          required: ['fayId', 'resourceId', 'operationId', 'requestedMode'],
          additionalProperties: false,
          properties: {
            requestId: { type: 'string' },
            fayId: { type: 'string' },
            resourceId: { type: 'string' },
            operationId: { type: 'string' },
            requestedMode: {
              type: 'string',
              enum: ['read', 'write', 'execute', 'configure'],
            },
            params: { type: 'object' },
            domainCategory: { type: 'string' },
            g0Override: { type: 'boolean' },
            callerCriticalityOverride: {
              type: 'string',
              enum: ['routine', 'sensitive', 'high', 'critical'],
            },
            nowEpochMs: { type: 'number' },
          },
        },
        policy: {
          type: 'object',
          description: 'Signed DriverCapabilityManifest, Ed25519 trust anchors, and grant floor.',
          required: ['manifest', 'trustAnchors'],
          additionalProperties: false,
          properties: {
            manifest: { type: 'object' },
            trustAnchors: { type: 'object' },
            grantId: { type: 'string' },
            allowedModes: {
              type: 'array',
              items: { type: 'string' },
            },
            minGrade: {
              type: 'string',
              enum: ['G1', 'G2', 'G3', 'G4'],
            },
            criticalityOverride: {
              type: 'string',
              enum: ['routine', 'sensitive', 'high', 'critical'],
            },
          },
        },
        mandate: {
          type: 'object',
          description:
            'Signed Faying 1.0 Mandate envelope (cryptographically verified) or CAP mandate_binding record.',
        },
        trustedIssuerPublicKeyHex: {
          type: 'string',
          description:
            'Optional Human Prime Ed25519 public key hex to verify a signed Faying 1.0 Mandate.',
        },
        humanConfirmation: {
          type: 'object',
          description:
            'Optional terminal-attested, parameter-bound Human Prime confirmation for high/critical actions.',
        },
        request: {
          type: 'object',
          description: 'Raw CAP 1.0 evaluation request object (alternative direct wire mode).',
        },
        trustAnchors: {
          type: 'object',
          description: 'Ed25519 trust anchor map when using direct request wire mode.',
        },
      },
    },
    annotations: {
      title: 'Evaluate CAP 1.0 Host/Tool Safety Gate',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: 'ssp_verify_descriptor',
    description:
      'Validate a Skill Sharing Protocol (SSP 1.0) skill descriptor and optionally verify its RFC 8785 JCS + Detached Ed25519 JWS (alg: EdDSA) SkillProof signature.',
    inputSchema: {
      type: 'object',
      required: ['descriptor'],
      additionalProperties: false,
      properties: {
        descriptor: {
          type: 'object',
          description: 'Candidate SSP 1.0 SkillDescriptor (signed or unsigned).',
        },
        trustedPublicKeyHex: {
          type: 'string',
          description:
            'Optional 32-byte raw Ed25519 publisher public key (64 hex chars) for JWS verification.',
        },
        consumerVersion: {
          type: 'string',
          description: 'Consumer SSP protocol version (two-segment MAJOR.MINOR, defaults to 1.0).',
        },
        requireAuthForRestricted: {
          type: 'boolean',
          description: 'Require authenticated callerFayId when visibility is restricted or private.',
        },
        callerFayId: {
          type: 'string',
          description: 'Authenticated caller FayID for restricted skill access checks.',
        },
      },
    },
    annotations: {
      title: 'Verify SSP 1.0 Skill Descriptor & Ed25519 Proof',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
] as const;

export function executeFayIdValidate(args: Record<string, unknown>): Record<string, unknown> {
  if (typeof args.fayId !== 'string') {
    throw new RpcParamsError("Invalid params: 'fayId' must be a string");
  }
  if (args.expectedKind !== undefined) {
    if (typeof args.expectedKind !== 'string' || !VALID_FAYID_KINDS.has(args.expectedKind)) {
      throw new RpcParamsError(
        `Invalid params: 'expectedKind' must be one of ${Array.from(VALID_FAYID_KINDS).join(', ')}`,
      );
    }
  }
  if (args.did !== undefined && typeof args.did !== 'string') {
    throw new RpcParamsError("Invalid params: 'did' must be a string");
  }
  if (args.publicKeyHex !== undefined && typeof args.publicKeyHex !== 'string') {
    throw new RpcParamsError("Invalid params: 'publicKeyHex' must be a string");
  }
  if (args.challengeUtf8 !== undefined && typeof args.challengeUtf8 !== 'string') {
    throw new RpcParamsError("Invalid params: 'challengeUtf8' must be a string");
  }
  if (args.signatureHex !== undefined && typeof args.signatureHex !== 'string') {
    throw new RpcParamsError("Invalid params: 'signatureHex' must be a string");
  }

  const errors: string[] = [];
  const parsed = parseFayId(args.fayId);
  if (!parsed.ok) {
    errors.push(parsed.error);
    return {
      valid: false,
      input: args.fayId,
      errors,
    };
  }

  const { kind, prefix, body, value: normalized } = parsed.value;
  const isUppercaseInput = args.fayId !== normalized;
  if (isUppercaseInput) {
    errors.push('NON_CANONICAL_UPPERCASE_FAYID');
  }

  if (args.expectedKind && kind !== (args.expectedKind as FayIdKind)) {
    errors.push(`KIND_MISMATCH: expected ${args.expectedKind}, got ${kind}`);
  }

  const decoded = kind === 'ORGANIZATION_ID' ? null : base32DecodeNoPad(body);
  if (
    (kind === 'HUMAN_ID' || kind === 'IFAY_ID' || kind === 'COFAY_ID') &&
    (!decoded || decoded.length < 16)
  ) {
    errors.push('INSUFFICIENT_ENTITY_ID_BYTES');
  }

  let didConsistent: boolean | undefined;
  if (typeof args.did === 'string') {
    const expectedDid = `did:fay:${normalized}`;
    didConsistent = args.did === expectedDid;
    if (!didConsistent) {
      errors.push(`DID_MISMATCH: expected '${expectedDid}', got '${args.did}'`);
    }
  }

  let keyBindingVerified: boolean | undefined;
  if (typeof args.publicKeyHex === 'string') {
    if (!isValidEd25519PublicKeyHex(args.publicKeyHex)) {
      keyBindingVerified = false;
      errors.push('INVALID_ED25519_PUBLIC_KEY_HEX');
    } else if (kind === 'HUMAN_ID' || kind === 'IFAY_ID' || kind === 'COFAY_ID') {
      const digest = createHash('sha256')
        .update(Buffer.from(args.publicKeyHex, 'hex'))
        .digest();
      const expectedEntityId = `${prefix}${base32EncodeNoPad(digest)}`;
      keyBindingVerified = expectedEntityId === normalized;
      if (!keyBindingVerified) {
        errors.push('PUBLIC_KEY_HASH_MISMATCH_WITH_FAYID');
      }
    } else {
      keyBindingVerified = true;
    }
  }

  let holderOfKeyVerified: boolean | undefined;
  if (args.signatureHex !== undefined || args.challengeUtf8 !== undefined) {
    if (
      typeof args.publicKeyHex !== 'string' ||
      typeof args.challengeUtf8 !== 'string' ||
      typeof args.signatureHex !== 'string'
    ) {
      holderOfKeyVerified = false;
      errors.push('HOLDER_OF_KEY_REQUIRES_PUBLIC_KEY_CHALLENGE_AND_SIGNATURE');
    } else {
      holderOfKeyVerified = verifyEd25519(
        args.publicKeyHex,
        Buffer.from(args.challengeUtf8, 'utf8'),
        args.signatureHex,
      );
      if (!holderOfKeyVerified) {
        errors.push('HOLDER_OF_KEY_SIGNATURE_INVALID');
      }
    }
  }

  return {
    valid: errors.length === 0,
    normalized,
    kind,
    prefix,
    bodyLength: body.length,
    decodedByteLength: decoded ? decoded.length : null,
    ...(didConsistent !== undefined ? { didConsistent } : {}),
    ...(keyBindingVerified !== undefined ? { keyBindingVerified } : {}),
    ...(holderOfKeyVerified !== undefined ? { holderOfKeyVerified } : {}),
    errors,
  };
}

export function executeFayManifestValidate(args: Record<string, unknown>): Record<string, unknown> {
  if (!isPlainObject(args.manifest)) {
    throw new RpcParamsError("Invalid params: 'manifest' must be a JSON object");
  }

  const candidate = args.manifest;
  const schemaResult = validateFayManifest(candidate);
  const errors = [...schemaResult.errors];

  if (typeof candidate.fayId === 'string') {
    const parsedId = parseFayId(candidate.fayId);
    if (
      !parsedId.ok ||
      (parsedId.value.kind !== 'IFAY_ID' && parsedId.value.kind !== 'COFAY_ID') ||
      candidate.fayId !== parsedId.value.value
    ) {
      errors.push('$.fayId must be a canonical lowercase ifay_ or cofay_ identifier');
    }
  }

  const valid = errors.length === 0;
  let summary: Record<string, unknown> | null = null;
  if (valid) {
    const typedManifest = candidate as unknown as FayManifest;
    const deps = resolveFayManifestDependencies(typedManifest);
    const phase = classifyFayManifestPhase(typedManifest);
    summary = {
      name: typedManifest.name,
      version: typedManifest.version,
      vendor: typedManifest.vendor,
      controlMode: typedManifest.controlMode,
      fayId: typedManifest.fayId ?? null,
      resolvedPhase: phase.phase,
      phaseNumber: phase.phaseNumber,
      requiredStages: phase.requiredStages,
      declaredModuleCount: typedManifest.modules.length,
      resolvedModules: deps.modules,
      autoCompletedModules: deps.autoCompletedModules,
      resolvedProtocols: deps.protocols,
      autoCompletedProtocols: deps.autoCompletedProtocols,
      driverNamespaces: deps.driverNamespaces,
      egoNamespace: deps.egoNamespace,
    };
  }

  return {
    valid,
    errorCount: errors.length,
    errors,
    summary,
  };
}

const CAP_RULE_BY_ERROR_CODE: Readonly<Record<string, string>> = Object.freeze({
  E_UNTRUSTED_MANIFEST: 'D-1:UNTRUSTED_DRIVER_CAPABILITY_MANIFEST',
  E_GRADE_INSUFFICIENT: 'D-2:SESSION_GRADE_MATRIX_INSUFFICIENT',
  E_G0_EMERGENCY_OVERRIDE: 'D-3:G0_HUMAN_PRIME_SAFE_STATE_OVERRIDE',
  E_MANDATE_INVALID: 'D-4:MANDATE_OR_GRANT_SCOPE_INVALID',
  E_WEAK_MANDATE_BINDING: 'D-4:WEAK_MANDATE_SESSION_BINDING',
  E_UNKNOWN_OPERATION: 'D-5:UNKNOWN_OPERATION_DEFAULT_CRITICAL_DENY',
  E_CONFIRMATION_REQUIRED: 'D-6/D-7:PARAMETER_BOUND_HUMAN_CONFIRMATION_REQUIRED',
  E_OUT_OF_SCOPE_FUND_TRANSFER: 'D-7c:OUT_OF_SCOPE_FUND_TRANSFER_EXCLUDED',
  E_PROTOCOL_VERSION_UNSUPPORTED: 'CAP-1.0:UNSUPPORTED_PROTOCOL_VERSION',
});

export function executeCapEvaluate(args: Record<string, unknown>): Record<string, unknown> {
  let capReq: Record<string, unknown>;
  let trustAnchors: Record<string, { algorithm: string; public_key_raw_hex: string }>;
  let mandateSignatureVerified: boolean | null = null;

  if (isPlainObject(args.request) && isPlainObject(args.trustAnchors)) {
    capReq = structuredClone(args.request);
    trustAnchors = args.trustAnchors as Record<
      string,
      { algorithm: string; public_key_raw_hex: string }
    >;
  } else if (
    isPlainObject(args.action) &&
    isPlainObject(args.policy) &&
    isPlainObject(args.mandate)
  ) {
    const action = args.action;
    const policy = args.policy;
    const mandateObj = args.mandate;

    if (
      typeof action.fayId !== 'string' ||
      typeof action.resourceId !== 'string' ||
      typeof action.operationId !== 'string' ||
      typeof action.requestedMode !== 'string'
    ) {
      throw new RpcParamsError(
        "Invalid params: 'action' requires string fields fayId, resourceId, operationId, requestedMode",
      );
    }
    if (!isPlainObject(policy.manifest) || !isPlainObject(policy.trustAnchors)) {
      throw new RpcParamsError(
        "Invalid params: 'policy' requires object fields manifest and trustAnchors",
      );
    }

    const nowEpochMs = typeof action.nowEpochMs === 'number' ? action.nowEpochMs : Date.now();
    trustAnchors = policy.trustAnchors as Record<
      string,
      { algorithm: string; public_key_raw_hex: string }
    >;

    let mandateBinding: Record<string, unknown>;
    if (mandateObj.protocolVersion === '1.0' && isPlainObject(mandateObj.signature)) {
      const typedMandate = mandateObj as unknown as FayingMandate;
      const sigCheck = verifyFayingMandate(typedMandate, {
        trustedIssuerPublicKeyHex:
          typeof args.trustedIssuerPublicKeyHex === 'string'
            ? args.trustedIssuerPublicKeyHex
            : undefined,
        nowEpochMs,
      });

      if (!sigCheck.valid && sigCheck.errorCode === 'E_SIGNATURE_INVALID') {
        const paramsObj = isPlainObject(action.params) ? action.params : {};
        const paramsSha256 = computeCapParamsSha256(paramsObj);
        const traceCore = {
          requestId: typeof action.requestId === 'string' ? action.requestId : 'mcp_cap_req',
          fayId: action.fayId,
          resourceId: action.resourceId,
          operationId: action.operationId,
          requestedMode: action.requestedMode,
          paramsSha256,
          decision: 'DENY',
          errorCode: 'E_MANDATE_INVALID',
          mandateSignatureVerified: false,
          evaluatedAtEpochMs: nowEpochMs,
        };
        const decisionDigestSha256 = createHash('sha256')
          .update(canonicalizeJcs(traceCore), 'utf8')
          .digest('hex');

        return {
          decision: 'DENY',
          rule: 'D-4:MANDATE_ED25519_SIGNATURE_INVALID',
          effectiveCriticality: 'critical',
          escalationClamped: false,
          errorCode: 'E_MANDATE_INVALID',
          diagnosticCode: 2008,
          reason: 'Signed Faying 1.0 Mandate failed Ed25519 JCS signature verification',
          auditTrace: {
            ...traceCore,
            decisionDigestSha256,
          },
        };
      }

      mandateSignatureVerified = true;
      const targetResource = typedMandate.scope?.resources?.includes(action.resourceId)
        ? action.resourceId
        : (typedMandate.scope?.resources?.[0] ?? '__unscoped__');
      mandateBinding = toCapMandateBinding(typedMandate, targetResource);
    } else {
      mandateBinding = structuredClone(mandateObj);
    }

    const allowedModes = Array.isArray(policy.allowedModes)
      ? (policy.allowedModes as string[])
      : Array.isArray(mandateBinding.allowed_modes)
        ? (mandateBinding.allowed_modes as string[])
        : ['read'];

    const minGrade: FayingGrade =
      typeof policy.minGrade === 'string' ? (policy.minGrade as FayingGrade) : 'G3';

    capReq = {
      protocol_version: '1.0',
      request_id: typeof action.requestId === 'string' ? action.requestId : 'mcp_cap_req',
      fay_id: action.fayId,
      now_epoch_ms: nowEpochMs,
      resource_id: action.resourceId,
      operation_id: action.operationId,
      requested_mode: action.requestedMode,
      params: isPlainObject(action.params) ? action.params : {},
      ...(typeof action.domainCategory === 'string'
        ? { domain_category: action.domainCategory }
        : {}),
      ...(typeof action.g0Override === 'boolean' ? { g0_override: action.g0Override } : {}),
      ...(typeof action.callerCriticalityOverride === 'string'
        ? { caller_criticality_override: action.callerCriticalityOverride }
        : {}),
      manifest: policy.manifest,
      grant: {
        grant_id: typeof policy.grantId === 'string' ? policy.grantId : 'grt_mcp_gate',
        resource_id: action.resourceId,
        allowed_modes: allowedModes,
        min_grade: minGrade,
        ...(typeof policy.criticalityOverride === 'string'
          ? { criticality_override: policy.criticalityOverride }
          : {}),
        mandate_binding: mandateBinding,
      },
      ...(isPlainObject(args.humanConfirmation)
        ? { human_confirmation: args.humanConfirmation }
        : {}),
    };
  } else {
    throw new RpcParamsError(
      "Invalid params: provide either { action, policy, mandate } or { request, trustAnchors }",
    );
  }

  const evalResult = evaluateCapAction(capReq, trustAnchors);
  const paramsRecord = isPlainObject(capReq.params) ? capReq.params : {};
  const paramsSha256 = computeCapParamsSha256(paramsRecord);
  const manifestObj = isPlainObject(capReq.manifest) ? capReq.manifest : {};
  const grantObj = isPlainObject(capReq.grant) ? capReq.grant : {};
  const bindingObj = isPlainObject(grantObj.mandate_binding) ? grantObj.mandate_binding : {};

  const rule =
    evalResult.decision === 'ALLOW'
      ? 'CAP-1.0-ALLOW:POLICY_AND_MANDATE_SATISFIED'
      : (CAP_RULE_BY_ERROR_CODE[evalResult.error_code ?? ''] ?? 'CAP-1.0-DENY');

  const traceCore = {
    requestId: String(capReq.request_id ?? 'mcp_cap_req'),
    fayId: String(capReq.fay_id ?? ''),
    resourceId: String(capReq.resource_id ?? ''),
    operationId: String(capReq.operation_id ?? ''),
    requestedMode: String(capReq.requested_mode ?? ''),
    paramsSha256,
    driverManifestId: String(manifestObj.manifest_id ?? 'unknown'),
    mandateId: String(bindingObj.mandate_id ?? 'unknown'),
    mandateSignatureVerified,
    decision: evalResult.decision,
    rule,
    effectiveCriticality: evalResult.effective_criticality,
    ...(evalResult.effective_grade !== undefined ? { effectiveGrade: evalResult.effective_grade } : {}),
    ...(evalResult.error_code !== undefined ? { errorCode: evalResult.error_code } : {}),
    evaluatedAtEpochMs:
      typeof capReq.now_epoch_ms === 'number' ? capReq.now_epoch_ms : Date.now(),
  };

  const decisionDigestSha256 = createHash('sha256')
    .update(canonicalizeJcs(traceCore), 'utf8')
    .digest('hex');

  return {
    decision: evalResult.decision,
    rule,
    effectiveCriticality: evalResult.effective_criticality,
    ...(evalResult.effective_grade !== undefined
      ? { effectiveGrade: evalResult.effective_grade }
      : {}),
    escalationClamped: evalResult.escalation_clamped,
    ...(evalResult.error_code !== undefined ? { errorCode: evalResult.error_code } : {}),
    ...(evalResult.diagnostic_code !== undefined
      ? { diagnosticCode: evalResult.diagnostic_code }
      : {}),
    ...(evalResult.reason !== undefined ? { reason: evalResult.reason } : {}),
    ...(evalResult.safe_state_directive !== undefined
      ? { safeStateDirective: evalResult.safe_state_directive }
      : {}),
    auditTrace: {
      ...traceCore,
      decisionDigestSha256,
    },
  };
}

export function executeSspVerifyDescriptor(args: Record<string, unknown>): Record<string, unknown> {
  if (!isPlainObject(args.descriptor)) {
    throw new RpcParamsError("Invalid params: 'descriptor' must be a JSON object");
  }
  if (args.trustedPublicKeyHex !== undefined && typeof args.trustedPublicKeyHex !== 'string') {
    throw new RpcParamsError("Invalid params: 'trustedPublicKeyHex' must be a string");
  }
  if (args.consumerVersion !== undefined && typeof args.consumerVersion !== 'string') {
    throw new RpcParamsError("Invalid params: 'consumerVersion' must be a string");
  }
  if (
    args.requireAuthForRestricted !== undefined &&
    typeof args.requireAuthForRestricted !== 'boolean'
  ) {
    throw new RpcParamsError("Invalid params: 'requireAuthForRestricted' must be a boolean");
  }
  if (args.callerFayId !== undefined && typeof args.callerFayId !== 'string') {
    throw new RpcParamsError("Invalid params: 'callerFayId' must be a string");
  }

  const descriptor = args.descriptor;
  const consumerVersion = args.consumerVersion ?? '1.0';
  const errors: string[] = [];

  const { proof, ...unsignedDescriptor } = descriptor;

  if (unsignedDescriptor.protocol !== 'ssp/1.0') {
    errors.push("$.protocol must equal 'ssp/1.0'");
  }
  const versionCompatible =
    typeof unsignedDescriptor.version === 'string' &&
    isSspVersionCompatible(unsignedDescriptor.version, consumerVersion);
  if (!versionCompatible) {
    errors.push(
      `$.version '${String(unsignedDescriptor.version)}' is incompatible with consumer version '${consumerVersion}'`,
    );
  }
  if (typeof unsignedDescriptor.skillId !== 'string' || unsignedDescriptor.skillId.trim().length === 0) {
    errors.push('$.skillId must be a non-empty string');
  }
  if (typeof unsignedDescriptor.name !== 'string' || unsignedDescriptor.name.trim().length === 0) {
    errors.push('$.name must be a non-empty string');
  }

  const pubParsed =
    typeof unsignedDescriptor.publisherFayId === 'string'
      ? parseFayId(unsignedDescriptor.publisherFayId)
      : { ok: false as const, error: 'MALFORMED_FAYID_STRING' };
  if (
    !pubParsed.ok ||
    (pubParsed.value.kind !== 'IFAY_ID' && pubParsed.value.kind !== 'COFAY_ID') ||
    unsignedDescriptor.publisherFayId !== pubParsed.value.value
  ) {
    errors.push('$.publisherFayId must be a canonical lowercase ifay_ or cofay_ identifier');
  }

  if (typeof unsignedDescriptor.origin !== 'string' || !/^https?:\/\/.+/.test(unsignedDescriptor.origin)) {
    errors.push('$.origin must be a valid http(s) URL string');
  }
  if (
    typeof unsignedDescriptor.visibility !== 'string' ||
    !['public', 'restricted', 'private'].includes(unsignedDescriptor.visibility)
  ) {
    errors.push("$.visibility must be one of 'public', 'restricted', 'private'");
  }
  if (
    typeof unsignedDescriptor.executionMode !== 'string' ||
    !['sync', 'async', 'stream'].includes(unsignedDescriptor.executionMode)
  ) {
    errors.push("$.executionMode must be one of 'sync', 'async', 'stream'");
  }
  if (!isPlainObject(unsignedDescriptor.inputSchema)) {
    errors.push('$.inputSchema must be a JSON Schema object');
  }
  if (!isPlainObject(unsignedDescriptor.outputSchema)) {
    errors.push('$.outputSchema must be a JSON Schema object');
  }

  const structuralValid = errors.length === 0;
  const descriptorJcsSha256 = createHash('sha256')
    .update(canonicalizeJcs(unsignedDescriptor), 'utf8')
    .digest('hex');

  const signaturePresent = isPlainObject(proof);
  let signatureVerified = false;
  let signatureStatus: string = 'unsigned';
  let errorCode: string | undefined;
  let kid: string | null = signaturePresent && typeof proof.kid === 'string' ? proof.kid : null;

  if (typeof args.trustedPublicKeyHex === 'string') {
    if (!isValidEd25519PublicKeyHex(args.trustedPublicKeyHex)) {
      errorCode = 'SSP_INVALID_PUBLIC_KEY_HEX';
      signatureStatus = 'invalid_public_key';
      errors.push('trustedPublicKeyHex is not a valid 32-byte Ed25519 public key');
    } else {
      const verifyRes = verifySkillDescriptor(descriptor, {
        trustedPublicKeyHex: args.trustedPublicKeyHex,
        consumerVersion,
        requireAuthForRestricted: Boolean(args.requireAuthForRestricted),
        callerFayId: args.callerFayId,
      });
      if (verifyRes.valid) {
        signatureVerified = true;
        signatureStatus = 'verified_ed25519_detached_jws';
        kid = verifyRes.kid ?? kid;
      } else {
        signatureVerified = false;
        signatureStatus = 'verification_failed';
        errorCode = verifyRes.errorCode ?? 'SSP_SIGNATURE_INVALID';
        errors.push(`Detached Ed25519 JWS verification failed: ${errorCode}`);
      }
    }
  } else if (signaturePresent) {
    if (
      proof.alg !== 'EdDSA' ||
      typeof proof.jws !== 'string' ||
      proof.jws.split('.').length !== 3 ||
      proof.jws.split('.')[1] !== ''
    ) {
      signatureStatus = 'malformed_detached_jws';
      errorCode = 'SSP_MALFORMED_DETACHED_JWS';
      errors.push('$.proof must contain a valid 3-part detached JWS with alg=EdDSA');
    } else {
      signatureStatus = 'unverified_no_trusted_key';
    }
  }

  return {
    valid: structuralValid && errors.length === 0,
    structuralValid,
    versionCompatible,
    signaturePresent,
    signatureVerified,
    signatureStatus,
    publisherFayId: pubParsed.ok ? pubParsed.value.value : null,
    kid,
    descriptorJcsSha256,
    ...(errorCode ? { errorCode } : {}),
    errors,
  };
}

export class IfayMcpServer {
  private negotiatedVersion = '2025-03-26';

  handleMessage(rawMessage: unknown): JsonRpcResponse | null {
    if (!isPlainObject(rawMessage)) {
      return {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: JSONRPC_ERRORS.INVALID_REQUEST,
          message: 'Invalid Request: JSON-RPC message must be an object',
        },
      };
    }

    const hasId = 'id' in rawMessage && rawMessage.id !== undefined;
    const rawId = hasId ? (rawMessage.id as string | number | null) : null;

    if (rawMessage.jsonrpc !== '2.0' || typeof rawMessage.method !== 'string') {
      return {
        jsonrpc: '2.0',
        id: rawId,
        error: {
          code: JSONRPC_ERRORS.INVALID_REQUEST,
          message: "Invalid Request: requires jsonrpc='2.0' and string 'method'",
        },
      };
    }

    // Notifications (no `id` field) must not produce JSON-RPC response frames
    if (!hasId) {
      return null;
    }

    try {
      const result = this.dispatchMethod(rawMessage.method, rawMessage.params);
      return {
        jsonrpc: '2.0',
        id: rawId,
        result,
      };
    } catch (err) {
      if (err instanceof RpcParamsError) {
        return {
          jsonrpc: '2.0',
          id: rawId,
          error: {
            code: JSONRPC_ERRORS.INVALID_PARAMS,
            message: err.message,
            ...(err.data !== undefined ? { data: err.data } : {}),
          },
        };
      }
      if (err instanceof Error && err.message.startsWith('Method not found:')) {
        return {
          jsonrpc: '2.0',
          id: rawId,
          error: {
            code: JSONRPC_ERRORS.METHOD_NOT_FOUND,
            message: err.message,
          },
        };
      }
      return {
        jsonrpc: '2.0',
        id: rawId,
        error: {
          code: JSONRPC_ERRORS.INTERNAL_ERROR,
          message: err instanceof Error ? err.message : 'Internal error',
        },
      };
    }
  }

  handleJsonLine(line: string): JsonRpcResponse | null {
    const trimmed = line.trim();
    if (trimmed.length === 0) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      return {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: JSONRPC_ERRORS.PARSE_ERROR,
          message: 'Parse error: malformed JSON-RPC frame',
        },
      };
    }
    return this.handleMessage(parsed);
  }

  private dispatchMethod(method: string, params: unknown): unknown {
    switch (method) {
      case 'initialize': {
        if (params !== undefined && !isPlainObject(params)) {
          throw new RpcParamsError("Invalid params: 'initialize' params must be an object");
        }
        const requested = isPlainObject(params) ? params.protocolVersion : undefined;
        if (
          typeof requested === 'string' &&
          (SUPPORTED_MCP_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
        ) {
          this.negotiatedVersion = requested;
        } else {
          this.negotiatedVersion = SUPPORTED_MCP_PROTOCOL_VERSIONS[0];
        }
        return {
          protocolVersion: this.negotiatedVersion,
          capabilities: {
            tools: {
              listChanged: false,
            },
          },
          serverInfo: {
            name: MCP_SERVER_NAME,
            version: MCP_SERVER_VERSION,
          },
          instructions:
            'Cryptographic identity, FayManifest schema, CAP 1.0 Host safety-gate, and SSP 1.0 skill-proof verification tools for sovereign iFay agents.',
        };
      }

      case 'ping': {
        return {};
      }

      case 'tools/list': {
        return {
          tools: MCP_TOOLS,
        };
      }

      case 'tools/call': {
        if (!isPlainObject(params) || typeof params.name !== 'string') {
          throw new RpcParamsError(
            "Invalid params: 'tools/call' requires an object with string 'name'",
          );
        }
        const toolArgs = params.arguments === undefined ? {} : params.arguments;
        if (!isPlainObject(toolArgs)) {
          throw new RpcParamsError(
            "Invalid params: 'tools/call' field 'arguments' must be a JSON object",
          );
        }

        let payload: Record<string, unknown>;
        switch (params.name) {
          case 'fayid_validate':
            payload = executeFayIdValidate(toolArgs);
            break;
          case 'faymanifest_validate':
            payload = executeFayManifestValidate(toolArgs);
            break;
          case 'cap_evaluate':
            payload = executeCapEvaluate(toolArgs);
            break;
          case 'ssp_verify_descriptor':
            payload = executeSspVerifyDescriptor(toolArgs);
            break;
          default:
            throw new RpcParamsError(`Invalid params: unknown tool '${params.name}'`);
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(payload, null, 2),
            },
          ],
          structuredContent: payload,
          isError: false,
        };
      }

      default:
        throw new Error(`Method not found: ${method}`);
    }
  }
}

export function attachStdioTransport(
  server: IfayMcpServer,
  input: Readable = process.stdin,
  output: Writable = process.stdout,
): { close: () => void } {
  const rl = createInterface({
    input,
    crlfDelay: Infinity,
  });

  rl.on('line', (line) => {
    const response = server.handleJsonLine(line);
    if (response !== null) {
      output.write(`${JSON.stringify(response)}\n`);
    }
  });

  return {
    close: () => rl.close(),
  };
}
