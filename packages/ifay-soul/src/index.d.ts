import type { FayManifest } from '@ifay/sdk';

export type ThoughtSubtype = 'content' | 'data' | 'knowledge_base' | 'info_feed';
export type SkillType = 'api' | 'workflow' | 'bot' | 'agent' | 'app' | 'microservice';
export type HardwareSubtype = 'device' | 'storage' | 'computing';
export type PermissionLifecycle = 'inherent' | 'persistent' | 'ephemeral';
export type PlatformCategory = 'real_name' | 'expert' | 'commerce' | 'service' | 'social';
export type DeviceTier = 'super' | 'plus' | 'normal' | 'lite' | 'thin';
export type RoleArchetype = 'org_service' | 'functional_post' | 'project_collaborator';

export interface BufSectionInput {
  id: string;
  kind?: 'code' | 'data' | 'asset' | 'signature' | { custom: string };
  payload: Uint8Array | Buffer | string;
  visibility?: 'required' | 'optional';
  profile_constraints?: {
    required_capabilities?: string[];
    max_size?: number;
    required_features?: string[];
  };
}

export interface PackBufOptions {
  formatVersion?: number;
  schemaVersion?: string;
  runtimeInterfaceMin?: string;
  entry?: string;
  deprecationNotice?: string;
  runtime?: {
    preferred_impl?: string;
    selection_strategy: 'strict' | 'prefer_then_any' | 'any';
  };
  capabilities?: string[];
  quotas?: {
    cpu_ms_per_sec?: number;
    memory_bytes?: number;
    io_bytes_per_sec?: number;
  };
  sections?: BufSectionInput[];
  extensions?: Record<string, unknown>;
  signer?: {
    seed32: Uint8Array | string;
    publicKeyRef: string;
  };
}

export interface ParsedBufObject {
  header: {
    magic: string;
    formatVersion: number;
    manifestOffset: number;
    manifestLength: number;
    sectionIndexOffset: number;
    sectionIndexLength: number;
    sectionsOffset: number;
  };
  manifest: Record<string, unknown>;
  sectionIndex: Array<Record<string, unknown>>;
  sections: Array<{
    id: string;
    kind: string | { custom: string };
    visibility: 'required' | 'optional';
    digestHex: string;
    payload: Buffer;
  }>;
  trailer: {
    totalLength: number;
    manifestDigestHex: string;
    crc32: number;
  };
  verified: {
    digestValid: boolean;
    crc32Valid: boolean;
    signatureStatus: 'absent' | 'valid' | 'unverified';
  };
}

export interface DeviceRuntimeProfile {
  schema_version?: 'fayger-device-profile/1.0';
  device_id?: string;
  platform_id?: string;
  tier?: DeviceTier;
  memory_mb?: number;
  free_storage_mb?: number;
  network_online?: boolean;
  remote_only?: boolean;
  granted_capabilities?: string[];
  preferred_domains?: string[];
  ego_slot?: string | null;
  primary_body_endpoint?: string;
}

export declare function crc32Ieee(input: Uint8Array | Buffer | string): number;
export declare function encodeCanonicalCbor(value: unknown): Buffer;
export declare function decodeCanonicalCbor(bytes: Uint8Array | Buffer): unknown;
export declare function packBufBinary(spec?: PackBufOptions): Buffer;
export declare function parseBufBinary(
  bytes: Uint8Array | Buffer,
  options?: {
    verifyDigest?: boolean;
    trustedPublicKeyHex?: string;
    trustAnchors?: Record<string, string>;
    requireSignatureVerification?: boolean;
  },
): ParsedBufObject;
export declare function formatBufInspection(parsed: ParsedBufObject): string;

export declare function validateIfayProfile(profile: unknown): { valid: boolean; errors: string[] };
export declare function packDtpPersonalContextFrame(
  context: Record<string, unknown>,
  sessionKey32: Uint8Array,
  iv12: Uint8Array,
): { jcsHeader: string; encryptedPayload: Buffer; wireFrame: Buffer };
export declare function ingestDtpContextFrame(
  wireFrameBytes: Uint8Array,
  sessionKey32: Uint8Array,
  options?: { createdAt?: string },
): { ok: true; header: Record<string, unknown>; thoughtItem: Record<string, unknown> } | { ok: false; errorCode: string };

export declare class PrimaryBodyStore {
  replicaId: string;
  dirPath: string | null;
  fayId: string;
  genesisHash: string;
  headHashes: string[];
  stateRootSha256: string;
  events: Array<Record<string, unknown>>;
  profile: Record<string, any>;
  fayManifest: FayManifest;
  static init(options?: Record<string, unknown>): PrimaryBodyStore;
  static createPeerReplica(
    source: PrimaryBodyStore,
    options?: { replicaId?: string; dirPath?: string | null },
  ): PrimaryBodyStore;
  static load(dirPath: string): PrimaryBodyStore;
  verifyLedger(): { valid: boolean; code?: string; genesisHash?: string; headHashes?: string[] };
  addThought(thought: Record<string, unknown>, options?: Record<string, unknown>): Record<string, unknown>;
  ingestDtpFrame(
    wireFrameBytes: Uint8Array,
    sessionKey32: Uint8Array,
    options?: Record<string, unknown>,
  ): { event: Record<string, unknown>; thoughtItem: Record<string, unknown> };
  registerSkill(skill: Record<string, unknown>, options?: Record<string, unknown>): Record<string, unknown>;
  addPersona(persona: Record<string, unknown>, options?: Record<string, unknown>): Record<string, unknown>;
  switchActiveEgo(personaId: string, options?: Record<string, unknown>): Record<string, unknown>;
  recordHumanCorrection(correction: Record<string, unknown>, options?: Record<string, unknown>): Record<string, unknown>;
  registerPlatform(registration: Record<string, unknown>, options?: Record<string, unknown>): Record<string, unknown>;
  revokePlatform(platformId: string, options?: Record<string, unknown>): Record<string, unknown>;
  commitEmbodimentDelta(delta: Record<string, unknown>, options?: Record<string, unknown>): Record<string, unknown>;
  save(): void;
}

export declare function syncPrimaryReplicas(
  replicaA: PrimaryBodyStore,
  replicaB: PrimaryBodyStore,
): {
  ok: boolean;
  errorCode?: string;
  soulFayId?: string;
  genesisHash?: string;
  totalEvents?: number;
  pulledIntoA?: number;
  pulledIntoB?: number;
  headHashes?: string[];
  stateRootSha256?: string;
  consistent?: boolean;
};

export declare function sliceSoulForDevice(
  primaryBody: PrimaryBodyStore,
  deviceProfile?: DeviceRuntimeProfile,
  options?: { signBuf?: boolean; issuedAt?: string },
): {
  mode: 'full_embodiment' | 'compact_edge_slice' | 'remote_primary_pointer';
  tier: DeviceTier;
  deviceProfile: Required<DeviceRuntimeProfile>;
  fayManifest: FayManifest;
  slicedProfile: Record<string, any>;
  remotePrimaryPointer?: Record<string, any>;
  sliceSummary: Record<string, any>;
  bufBytes: Buffer;
  parsedBuf: ParsedBufObject;
};

export declare class CofaySeatBuilder {
  static createSeat(options?: Record<string, unknown>): Record<string, any>;
  static rotateSteward(currentCharter: Record<string, any>, options: Record<string, unknown>): Record<string, any>;
  static createTransferEnvelope(currentCharter: Record<string, any>, options: Record<string, unknown>): Record<string, any>;
  static applyOwnershipTransfer(
    currentCharter: Record<string, any>,
    envelope: Record<string, any>,
    options?: Record<string, unknown>,
  ): { valid: boolean; errors: Array<Record<string, string>>; nextCharter?: Record<string, any> };
  static packSeatBuf(seat: Record<string, any>, options?: Record<string, unknown>): Buffer;
  static saveToDirectory(dirPath: string, seat: Record<string, any>, options?: Record<string, unknown>): {
    dirPath: string;
    bufPath: string;
    bufByteLength: number;
  };
  static loadFromDirectory(dirPath: string): Record<string, any>;
}

export declare function runSoulDemo(options?: { outDir?: string }): Record<string, any>;
export declare function formatSoulDemoReport(result: Record<string, any>): string;
