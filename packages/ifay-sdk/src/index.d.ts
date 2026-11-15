export type FayIdKind =
  | 'HUMAN_ID'
  | 'IFAY_ID'
  | 'COFAY_ID'
  | 'ORGANIZATION_ID'
  | 'DYNAMIC_CODE'
  | 'AUTHORIZATION_GRANT'
  | 'VERIFICATION_CODE'
  | 'OPAQUE_REF';

export type FayingGrade = 'G0' | 'G1' | 'G2' | 'G3' | 'G4';
export type ControlMode = 'command' | 'ego' | 'autonomous';
export type CapCriticality = 'routine' | 'sensitive' | 'high' | 'critical';
export type CapAccessMode = 'read' | 'write' | 'execute' | 'configure';

export declare const FAYID_PREFIXES: Readonly<{
  HUMAN_ID: 'hid_';
  IFAY_ID: 'ifay_';
  COFAY_ID: 'cofay_';
  ORGANIZATION_ID: 'org_';
  DYNAMIC_CODE: 'dyn_';
  AUTHORIZATION_GRANT: 'grt_';
  VERIFICATION_CODE: 'vrf_';
  OPAQUE_REF: 'gmcref_';
}>;

export declare const SUBKEY_DOMAINS: Readonly<{
  ENTITY: 'ifay.fayid.entity.v1';
  EGO_PACKAGE_SIGNING: 'ifay.ego.package-signing.v1';
  GMC_NATURAL_PERSON: 'ifay.gmc.natural-person.v1';
}>;

export declare const GOVERNED_PACKAGE_SCOPES: readonly string[];
export declare const CORE_INFRASTRUCTURE_MODULES: readonly string[];
export declare const FAYING_GRADES: readonly FayingGrade[];

export interface ParsedFayId {
  kind: FayIdKind;
  prefix: string;
  body: string;
  value: string;
}

export type Result<T> = { ok: true; value: T } | { ok: false; error: string };

export interface Ed25519Signer {
  publicKeyRaw: Buffer;
  publicKeyHex: string;
  signPayload(payloadBytes: Uint8Array): Buffer;
  toJSON(): Record<string, unknown>;
}

export interface DerivedEntityKeypair extends Ed25519Signer {
  entityId: string;
  kind: FayIdKind;
  domain: string;
  toPublicRecord(): Record<string, unknown>;
}

export interface FayingScope {
  resources: string[];
  actions: string[];
  domains: string[];
  terminals: string[];
}

export interface FayingMandate {
  protocolVersion: '1.0';
  mandateId: string;
  humanPrimeId: string;
  fayId: string;
  grade: FayingGrade;
  bindingModel: 'model_a_plus_b' | 'model_b_online_ref' | 'model_c_offline_cache';
  scope: FayingScope;
  deviceId: string | null;
  parentMandateId: string | null;
  chainDepth: number;
  issuedAtEpochMs: number;
  expiresAtEpochMs: number;
  revoked: boolean;
  issuerPublicKeyHex: string;
  signature: {
    alg: 'Ed25519';
    sigHex: string;
    chain: string[];
  };
}

export interface FayManifest {
  name: string;
  version: string;
  description: string;
  vendor: string;
  fayId?: string;
  modules: Array<{ id: string; version?: string; provider?: string; config?: Record<string, unknown> }>;
  protocols: Array<{ id: string; version?: string; config?: Record<string, unknown> }>;
  controlMode: ControlMode;
  drivers?: Array<{
    name: string;
    type: string;
    driverPackage: string;
    config?: Record<string, unknown>;
  }>;
  ego?: {
    modelSource: string;
    scenarioTags?: string[];
    constraints?: {
      skillBoundaries?: {
        allowed?: string[];
        restricted?: string[];
      };
    };
  };
  permissions?: {
    inherent?: string[];
    persistent?: string[];
    authMethods?: string[];
  };
}

export declare function canonicalizeJcs(value: unknown): string;
export declare function base32EncodeNoPad(bytes: Uint8Array): string;
export declare function base32DecodeNoPad(input: string): Buffer | null;
export declare function parseFayId(input: string): Result<ParsedFayId>;
export declare function isValidFayId(input: string, expectedKind?: FayIdKind): boolean;

export declare function ed25519KeypairFromSeed(seed32: Uint8Array): Ed25519Signer;
export declare function signEd25519(seed32: Uint8Array, payloadBytes: Uint8Array): Buffer;
export declare function verifyEd25519(
  publicKeyRawOrHex: Uint8Array | string,
  payloadBytes: Uint8Array,
  signatureBytesOrHex: Uint8Array | string,
): boolean;

export declare function derivePurposeSubkey(
  masterSeed: Uint8Array,
  domain: string,
  context?: string,
): Result<Ed25519Signer & { domain: string; context: string; toPublicRecord(): Record<string, unknown> }>;

export declare function deriveEntityKeypair(
  masterSeed: Uint8Array,
  entityPrefix: 'hid' | 'ifay' | 'cofay' | 'org',
  slotOrSlug?: number | string,
): Result<DerivedEntityKeypair>;

export declare function deriveEgoPackageSigningKey(
  masterSeed: Uint8Array,
  signerFayId: string,
  keyIndex?: number,
): Result<
  Ed25519Signer & {
    domain: string;
    signerFayId: string;
    keyIndex: number;
    signEgoPackageManifest(manifestOrBytes: unknown): {
      version: '1.0';
      domain: string;
      signerFayId: string;
      keyIndex: number;
      publicKeyHex: string;
      payloadDigestHex: string;
      signatureHex: string;
    };
    toPublicRecord(): Record<string, unknown>;
  }
>;

export declare function verifyEgoPackageEnvelope(
  envelope: Record<string, unknown>,
  manifestOrBytes: unknown,
): boolean;

export declare function deriveBlindGmcRef(
  humanIdOrBytes: string | Uint8Array,
  userBlindSalt: Uint8Array,
  namespace?: string,
): Result<string>;

export declare function createFayingMandate(
  input: {
    mandateId: string;
    humanPrimeId: string;
    fayId: string;
    grade: FayingGrade;
    bindingModel?: 'model_a_plus_b' | 'model_b_online_ref' | 'model_c_offline_cache';
    scope: Partial<FayingScope>;
    deviceId?: string | null;
    parentMandateId?: string | null;
    chainDepth?: number;
    issuedAtEpochMs: number;
    expiresAtEpochMs: number;
    revoked?: boolean;
    signatureChain?: string[];
  },
  signer: Ed25519Signer,
): FayingMandate;

export declare function verifyFayingMandate(
  mandate: FayingMandate,
  options?: {
    trustedIssuerPublicKeyHex?: string;
    nowEpochMs?: number;
    revokedMandateIds?: Set<string>;
    requiredResource?: string;
    requiredAction?: string;
    requiredDomain?: string;
    requiredTerminal?: string;
  },
): {
  valid: boolean;
  errorCode?: string;
  grade?: FayingGrade;
  mandateId?: string;
  fayId?: string;
  humanPrimeId?: string;
};

export declare function delegateFayingMandate(
  parentMandate: FayingMandate,
  request: {
    mandateId: string;
    childFayId: string;
    grade: FayingGrade;
    bindingModel?: 'model_a_plus_b' | 'model_b_online_ref' | 'model_c_offline_cache';
    scope: FayingScope;
    deviceId?: string | null;
    issuedAtEpochMs?: number;
    expiresAtEpochMs?: number;
  },
  signer: Ed25519Signer,
):
  | { ok: true; value: FayingMandate }
  | { ok: false; diagnosticCode: number; errorCode: string; reason: string };

export declare function triggerG0EmergencyTakeover(
  activeMandate: FayingMandate,
  humanPrimeSigner: Ed25519Signer,
  nowEpochMs?: number,
): FayingMandate;

export declare function toCapMandateBinding(
  mandate: FayingMandate,
  resourceId: string,
  options?: { onlineFresh?: boolean; modelADerivedProofValid?: boolean },
): Record<string, unknown>;

export declare function loadFayManifestSchema(): Record<string, unknown>;
export declare function createFayManifest(
  input: Omit<FayManifest, 'version' | 'modules' | 'protocols' | 'controlMode'> & {
    version?: string;
    modules?: Array<string | FayManifest['modules'][number]>;
    protocols?: Array<string | FayManifest['protocols'][number]>;
    controlMode?: ControlMode;
  },
): FayManifest;
export declare function validateFayManifest(manifest: unknown): { valid: boolean; errors: string[] };
export declare function classifyPackageNamespace(
  packageId: string,
): 'governed' | 'ungoverned' | 'invalid';
export declare function resolveFayManifestDependencies(manifest: FayManifest): {
  modules: string[];
  protocols: string[];
  autoCompletedModules: string[];
  autoCompletedProtocols: string[];
  driverNamespaces: Array<{ driverPackage: string; governance: string }>;
  egoNamespace: string | null;
};
export declare function classifyFayManifestPhase(manifest: FayManifest): {
  phase: 'Phase 1' | 'Phase 2' | 'Phase 3' | 'Phase 4' | 'Phase 5';
  phaseNumber: 1 | 2 | 3 | 4 | 5;
  requiredStages: string[];
};

export declare function computeCapParamsSha256(params: Record<string, unknown>): string;
export declare function signCapDriverManifest(
  unsignedManifest: Record<string, unknown>,
  seed32: Uint8Array,
): Record<string, unknown>;
export declare function verifyCapDriverManifest(
  manifest: Record<string, unknown>,
  trustAnchors: Record<string, { algorithm: string; public_key_raw_hex: string }>,
): boolean;
export declare function evaluateCapAction(
  req: Record<string, unknown>,
  trustAnchors: Record<string, { algorithm: string; public_key_raw_hex: string }>,
): {
  decision: 'ALLOW' | 'DENY';
  effective_criticality: CapCriticality;
  effective_grade?: FayingGrade;
  escalation_clamped: boolean;
  error_code?: string;
  diagnostic_code?: number;
  reason?: string;
  safe_state_directive?: {
    action: 'enter_safe_state' | 'terminate_and_alert';
    safe_state_id?: string;
    blocks_human_takeover: false;
  };
};

export declare function isSspVersionCompatible(
  descriptorVersion: string,
  consumerVersion?: string,
): boolean;
export declare function signSkillDescriptor(
  descriptor: Record<string, unknown>,
  options: { signer: Ed25519Signer; kid?: string; created?: string },
): Record<string, unknown> & {
  proof: {
    type: 'Ed25519JcsDetachedJws2025';
    alg: 'EdDSA';
    kid: string;
    created: string;
    jws: string;
  };
};
export declare function verifySkillDescriptor(
  signedDescriptor: Record<string, unknown>,
  options?: {
    trustedPublicKeyHex: string;
    consumerVersion?: string;
    requireAuthForRestricted?: boolean;
    callerFayId?: string;
  },
): { valid: boolean; errorCode?: string; publisherFayId?: string; kid?: string };

export declare function encodeDtpFrame(
  header: Record<string, unknown>,
  plaintextBytes: Uint8Array,
  sessionKeyBytes: Uint8Array,
  ivBytes: Uint8Array,
): { jcsHeader: string; encryptedPayload: Buffer; wireFrame: Buffer };
export declare function decodeDtpFrame(
  wireFrameBytes: Uint8Array,
  sessionKeyBytes: Uint8Array,
):
  | { ok: true; header: Record<string, unknown>; rawHeader: Record<string, unknown>; plaintext: Buffer }
  | { ok: false; errorCode: number; errorName: string };

export declare function deriveEgoVaultSubkeySeed(masterSeed: Uint8Array): Buffer;
export declare function signEgoVaultManifest(
  manifest: Record<string, unknown>,
  options: { masterSeed: Uint8Array; signerFayId: string; keyId?: string },
): Record<string, unknown>;
export declare function verifyEgoVaultManifest(
  manifest: Record<string, unknown>,
  options?: { trustedPublicKeyHex?: string },
): {
  valid: boolean;
  errorCode?: string;
  signerFayId?: string;
  publicKeyHex?: string;
  payloadJcsSha256?: string;
};
export declare function validateEgoFidelityPrivacy(
  fidelityReport: unknown,
): { valid: boolean; errorCode?: string };
