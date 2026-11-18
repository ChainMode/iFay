import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  hkdfSync,
  sign,
  verify,
} from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const RFC4648_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const BASE32_NOPAD_RE = /^[a-z2-7]+$/;
const ORG_BODY_RE = /^[a-z0-9-]+$/;
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const FAYMANIFEST_SCHEMA_PATH = fileURLToPath(
  new URL('../../../schema/faymanifest/faymanifest.schema.json', import.meta.url),
);
const PACKAGED_FAYMANIFEST_SCHEMA_PATH = fileURLToPath(
  new URL('../dist/faymanifest.schema.json', import.meta.url),
);
let cachedFayManifestSchema = null;

export const FAYID_PREFIXES = Object.freeze({
  HUMAN_ID: 'hid_',
  IFAY_ID: 'ifay_',
  COFAY_ID: 'cofay_',
  ORGANIZATION_ID: 'org_',
  DYNAMIC_CODE: 'dyn_',
  AUTHORIZATION_GRANT: 'grt_',
  VERIFICATION_CODE: 'vrf_',
  OPAQUE_REF: 'gmcref_',
});

export const SUBKEY_DOMAINS = Object.freeze({
  ENTITY: 'ifay.fayid.entity.v1',
  EGO_PACKAGE_SIGNING: 'ifay.ego.package-signing.v1',
  GMC_NATURAL_PERSON: 'ifay.gmc.natural-person.v1',
});

export const GOVERNED_PACKAGE_SCOPES = Object.freeze([
  '@ifay',
  '@ego-models',
  '@cap-drivers',
  '@drone-drivers',
]);

export const CORE_INFRASTRUCTURE_MODULES = Object.freeze([
  'fay_id',
  'fayger_runtime',
  'ifay_profile',
  'permission_system',
  'security_ethics_compliance',
  'multi_terminal_sync',
]);

export const FAYING_GRADES = Object.freeze(['G0', 'G1', 'G2', 'G3', 'G4']);

const FAYID_KIND_SPECS = [
  ['OPAQUE_REF', FAYID_PREFIXES.OPAQUE_REF, BASE32_NOPAD_RE],
  ['VERIFICATION_CODE', FAYID_PREFIXES.VERIFICATION_CODE, BASE32_NOPAD_RE],
  ['AUTHORIZATION_GRANT', FAYID_PREFIXES.AUTHORIZATION_GRANT, BASE32_NOPAD_RE],
  ['DYNAMIC_CODE', FAYID_PREFIXES.DYNAMIC_CODE, BASE32_NOPAD_RE],
  ['COFAY_ID', FAYID_PREFIXES.COFAY_ID, BASE32_NOPAD_RE],
  ['IFAY_ID', FAYID_PREFIXES.IFAY_ID, BASE32_NOPAD_RE],
  ['ORGANIZATION_ID', FAYID_PREFIXES.ORGANIZATION_ID, ORG_BODY_RE],
  ['HUMAN_ID', FAYID_PREFIXES.HUMAN_ID, BASE32_NOPAD_RE],
];

// ============================================================================
// 1. Canonical Serialization (RFC 8785 JCS), Base32, FayID & Ed25519 / HKDF
// ============================================================================

export function canonicalizeJcs(value) {
  if (value === null || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('Non-finite numbers cannot be canonicalized under RFC 8785 JCS');
    }
    return Object.is(value, -0) ? '0' : JSON.stringify(value);
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJcs(item === undefined ? null : item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJcs(value[k])}`).join(',')}}`;
  }
  throw new TypeError(`Unsupported JCS value type: ${typeof value}`);
}

export function base32EncodeNoPad(bytes) {
  const buf = Buffer.from(bytes);
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += RFC4648_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += RFC4648_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function base32DecodeNoPad(input) {
  if (typeof input !== 'string' || input.length === 0 || input.includes('=')) {
    return null;
  }
  const lower = input.toLowerCase();
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of lower) {
    const idx = RFC4648_ALPHABET.indexOf(ch);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function parseFayId(input) {
  if (typeof input !== 'string' || input.length === 0) {
    return { ok: false, error: 'MALFORMED_FAYID_STRING' };
  }
  const normalized = input.toLowerCase();
  const match = FAYID_KIND_SPECS.find(([, prefix]) => normalized.startsWith(prefix));
  if (!match) {
    return { ok: false, error: 'MALFORMED_FAYID_STRING' };
  }
  const [kind, prefix, bodyPattern] = match;
  const body = normalized.slice(prefix.length);
  if (body.length === 0 || !bodyPattern.test(body)) {
    return { ok: false, error: 'MALFORMED_FAYID_STRING' };
  }
  return { ok: true, value: { kind, prefix, body, value: normalized } };
}

export function isValidFayId(input, expectedKind) {
  const parsed = parseFayId(input);
  if (!parsed.ok) return false;
  return expectedKind ? parsed.value.kind === expectedKind : true;
}

export function ed25519KeypairFromSeed(seed32) {
  const buf = Buffer.from(seed32);
  if (buf.length !== 32) {
    throw new RangeError(`Ed25519 seed must be exactly 32 bytes, received ${buf.length}`);
  }
  const privKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, buf]),
    format: 'der',
    type: 'pkcs8',
  });
  const pubKey = createPublicKey(privKey);
  const spki = pubKey.export({ format: 'der', type: 'spki' });
  const publicKeyRaw = Buffer.from(spki.subarray(spki.length - 32));
  const publicKeyHex = publicKeyRaw.toString('hex');

  return {
    publicKeyRaw,
    publicKeyHex,
    signPayload(payloadBytes) {
      return sign(null, Buffer.from(payloadBytes), privKey);
    },
    toJSON() {
      return { publicKeyHex };
    },
  };
}

export function signEd25519(seed32, payloadBytes) {
  return ed25519KeypairFromSeed(seed32).signPayload(payloadBytes);
}

export function verifyEd25519(publicKeyRawOrHex, payloadBytes, signatureBytesOrHex) {
  try {
    const rawPub =
      typeof publicKeyRawOrHex === 'string'
        ? Buffer.from(publicKeyRawOrHex, 'hex')
        : Buffer.from(publicKeyRawOrHex);
    const sigBuf =
      typeof signatureBytesOrHex === 'string'
        ? Buffer.from(signatureBytesOrHex, 'hex')
        : Buffer.from(signatureBytesOrHex);
    if (rawPub.length !== 32 || sigBuf.length !== 64) return false;

    const pubKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawPub]),
      format: 'der',
      type: 'spki',
    });
    return verify(null, Buffer.from(payloadBytes), pubKey, sigBuf);
  } catch {
    return false;
  }
}

export function derivePurposeSubkey(masterSeed, domain, context = 'default') {
  if (!masterSeed || Buffer.from(masterSeed).length < 32) {
    return { ok: false, error: 'INSUFFICIENT_ENTROPY' };
  }
  if (typeof domain !== 'string' || !/^[a-z0-9._-]+$/i.test(domain.trim())) {
    return { ok: false, error: 'DOMAIN_SEPARATION_REQUIRED' };
  }
  const cleanDomain = domain.trim();
  const cleanContext = String(context ?? 'default');
  const salt = createHash('sha256').update(`fayid/subkey-salt/v1:${cleanDomain}`, 'utf8').digest();
  const subSeed32 = Buffer.from(
    hkdfSync(
      'sha256',
      Buffer.from(masterSeed),
      salt,
      Buffer.from(`${cleanDomain}:${cleanContext}`, 'utf8'),
      32,
    ),
  );
  const kp = ed25519KeypairFromSeed(subSeed32);
  subSeed32.fill(0);

  const publicRecord = Object.freeze({
    domain: cleanDomain,
    context: cleanContext,
    publicKeyHex: kp.publicKeyHex,
  });

  return {
    ok: true,
    value: {
      domain: cleanDomain,
      context: cleanContext,
      publicKeyRaw: kp.publicKeyRaw,
      publicKeyHex: kp.publicKeyHex,
      signPayload: kp.signPayload,
      toPublicRecord: () => publicRecord,
      toJSON: () => publicRecord,
    },
  };
}

export function deriveEntityKeypair(masterSeed, entityPrefix, slotOrSlug = 0) {
  const allowed = new Map([
    ['hid', 'HUMAN_ID'],
    ['ifay', 'IFAY_ID'],
    ['cofay', 'COFAY_ID'],
    ['org', 'ORGANIZATION_ID'],
  ]);
  if (!allowed.has(entityPrefix)) {
    return { ok: false, error: 'MALFORMED_FAYID_STRING' };
  }
  const subRes = derivePurposeSubkey(
    masterSeed,
    SUBKEY_DOMAINS.ENTITY,
    `${entityPrefix}:${slotOrSlug}`,
  );
  if (!subRes.ok) return subRes;

  const sub = subRes.value;
  const idDigest = createHash('sha256').update(sub.publicKeyRaw).digest();
  const entityId =
    entityPrefix === 'org' && typeof slotOrSlug === 'string' && ORG_BODY_RE.test(slotOrSlug)
      ? `org_${slotOrSlug}`
      : `${entityPrefix}_${base32EncodeNoPad(idDigest)}`;
  const kind = allowed.get(entityPrefix);

  const publicRecord = Object.freeze({
    kind,
    ...(entityPrefix === 'hid' ? {} : { entityId }),
    domain: SUBKEY_DOMAINS.ENTITY,
    publicKeyHex: sub.publicKeyHex,
  });

  return {
    ok: true,
    value: {
      entityId,
      kind,
      domain: SUBKEY_DOMAINS.ENTITY,
      publicKeyRaw: sub.publicKeyRaw,
      publicKeyHex: sub.publicKeyHex,
      signPayload: sub.signPayload,
      toPublicRecord: () => publicRecord,
      toJSON: () => publicRecord,
    },
  };
}

export function deriveEgoPackageSigningKey(masterSeed, signerFayId, keyIndex = 0) {
  const parsed = parseFayId(signerFayId);
  if (!parsed.ok || (parsed.value.kind !== 'IFAY_ID' && parsed.value.kind !== 'COFAY_ID')) {
    return { ok: false, error: 'MALFORMED_FAYID_STRING' };
  }
  if (!Number.isInteger(keyIndex) || keyIndex < 0) {
    return { ok: false, error: 'MALFORMED_FAYID_STRING' };
  }
  const normId = parsed.value.value;
  const subRes = derivePurposeSubkey(
    masterSeed,
    SUBKEY_DOMAINS.EGO_PACKAGE_SIGNING,
    `${normId}#${keyIndex}`,
  );
  if (!subRes.ok) return subRes;
  const sub = subRes.value;

  const publicRecord = Object.freeze({
    version: '1.0',
    domain: SUBKEY_DOMAINS.EGO_PACKAGE_SIGNING,
    signerFayId: normId,
    keyIndex,
    publicKeyHex: sub.publicKeyHex,
  });

  return {
    ok: true,
    value: {
      domain: SUBKEY_DOMAINS.EGO_PACKAGE_SIGNING,
      signerFayId: normId,
      keyIndex,
      publicKeyRaw: sub.publicKeyRaw,
      publicKeyHex: sub.publicKeyHex,
      signPayload: sub.signPayload,
      signEgoPackageManifest(manifestOrBytes) {
        const payloadBytes =
          Buffer.isBuffer(manifestOrBytes) || manifestOrBytes instanceof Uint8Array
            ? Buffer.from(manifestOrBytes)
            : Buffer.from(canonicalizeJcs(manifestOrBytes), 'utf8');
        const payloadDigestHex = createHash('sha256').update(payloadBytes).digest('hex');
        const signingCore = {
          version: '1.0',
          domain: SUBKEY_DOMAINS.EGO_PACKAGE_SIGNING,
          signerFayId: normId,
          keyIndex,
          publicKeyHex: sub.publicKeyHex,
          payloadDigestHex,
        };
        const sig = sub.signPayload(Buffer.from(canonicalizeJcs(signingCore), 'utf8'));
        return {
          ...signingCore,
          signatureHex: sig.toString('hex'),
        };
      },
      toPublicRecord: () => publicRecord,
      toJSON: () => publicRecord,
    },
  };
}

export function verifyEgoPackageEnvelope(envelope, manifestOrBytes) {
  try {
    if (
      !envelope ||
      envelope.version !== '1.0' ||
      envelope.domain !== SUBKEY_DOMAINS.EGO_PACKAGE_SIGNING
    ) {
      return false;
    }
    const parsed = parseFayId(envelope.signerFayId);
    if (!parsed.ok || (parsed.value.kind !== 'IFAY_ID' && parsed.value.kind !== 'COFAY_ID')) {
      return false;
    }
    const payloadBytes =
      Buffer.isBuffer(manifestOrBytes) || manifestOrBytes instanceof Uint8Array
        ? Buffer.from(manifestOrBytes)
        : Buffer.from(canonicalizeJcs(manifestOrBytes), 'utf8');
    const expectedDigest = createHash('sha256').update(payloadBytes).digest('hex');
    if (expectedDigest !== envelope.payloadDigestHex) return false;

    const signingCore = {
      version: '1.0',
      domain: envelope.domain,
      signerFayId: parsed.value.value,
      keyIndex: envelope.keyIndex,
      publicKeyHex: envelope.publicKeyHex,
      payloadDigestHex: envelope.payloadDigestHex,
    };
    return verifyEd25519(
      envelope.publicKeyHex,
      Buffer.from(canonicalizeJcs(signingCore), 'utf8'),
      envelope.signatureHex,
    );
  } catch {
    return false;
  }
}

export function deriveBlindGmcRef(
  humanIdOrBytes,
  userBlindSalt,
  namespace = SUBKEY_DOMAINS.GMC_NATURAL_PERSON,
) {
  if (!userBlindSalt || Buffer.from(userBlindSalt).length < 16) {
    return { ok: false, error: 'INSUFFICIENT_ENTROPY' };
  }
  if (typeof namespace !== 'string' || namespace.trim().length === 0) {
    return { ok: false, error: 'DOMAIN_SEPARATION_REQUIRED' };
  }
  let canonicalHumanBytes;
  if (typeof humanIdOrBytes === 'string') {
    const parsed = parseFayId(humanIdOrBytes);
    if (!parsed.ok || parsed.value.kind !== 'HUMAN_ID') {
      return { ok: false, error: 'MALFORMED_FAYID_STRING' };
    }
    canonicalHumanBytes = base32DecodeNoPad(parsed.value.body);
    if (!canonicalHumanBytes || canonicalHumanBytes.length === 0) {
      return { ok: false, error: 'MALFORMED_FAYID_STRING' };
    }
  } else if (Buffer.isBuffer(humanIdOrBytes) || humanIdOrBytes instanceof Uint8Array) {
    canonicalHumanBytes = Buffer.from(humanIdOrBytes);
    if (canonicalHumanBytes.length < 16) {
      return { ok: false, error: 'MALFORMED_FAYID_STRING' };
    }
  } else {
    return { ok: false, error: 'MALFORMED_FAYID_STRING' };
  }

  const derived = Buffer.from(
    hkdfSync(
      'sha256',
      Buffer.from(userBlindSalt),
      canonicalHumanBytes,
      Buffer.from(namespace.trim(), 'utf8'),
      32,
    ),
  );
  return { ok: true, value: `${FAYID_PREFIXES.OPAQUE_REF}${base32EncodeNoPad(derived)}` };
}

// ============================================================================
// 2. Faying 1.0 Handshake & Mandate Helper
// ============================================================================

const GRADE_AUTONOMY_INDEX = Object.freeze({
  G0: 0,
  G1: 1,
  G2: 2,
  G3: 3,
  G4: 4,
});

export function createFayingMandate(input, signer) {
  const hpParsed = parseFayId(input.humanPrimeId);
  const fayParsed = parseFayId(input.fayId);
  if (!hpParsed.ok || hpParsed.value.kind !== 'HUMAN_ID') {
    throw new Error(`Invalid humanPrimeId: ${input.humanPrimeId}`);
  }
  if (!fayParsed.ok || fayParsed.value.kind !== 'IFAY_ID') {
    throw new Error(`Invalid iFay subject fayId: ${input.fayId}`);
  }
  if (!FAYING_GRADES.includes(input.grade)) {
    throw new Error(`Unsupported Faying authorization grade: ${input.grade}`);
  }

  const unsignedMandate = {
    protocolVersion: '1.0',
    mandateId: input.mandateId,
    humanPrimeId: hpParsed.value.value,
    fayId: fayParsed.value.value,
    grade: input.grade,
    bindingModel: input.bindingModel ?? 'model_a_plus_b',
    scope: {
      resources: [...(input.scope?.resources ?? [])],
      actions: [...(input.scope?.actions ?? [])],
      domains: [...(input.scope?.domains ?? [])],
      terminals: [...(input.scope?.terminals ?? [])],
    },
    deviceId: input.deviceId ?? null,
    parentMandateId: input.parentMandateId ?? null,
    chainDepth: input.chainDepth ?? 0,
    issuedAtEpochMs: input.issuedAtEpochMs,
    expiresAtEpochMs: input.expiresAtEpochMs,
    revoked: Boolean(input.revoked ?? false),
    issuerPublicKeyHex: signer.publicKeyHex,
  };

  const canonicalBytes = Buffer.from(canonicalizeJcs(unsignedMandate), 'utf8');
  const sigBuf = signer.signPayload(canonicalBytes);

  return {
    ...unsignedMandate,
    signature: {
      alg: 'Ed25519',
      sigHex: sigBuf.toString('hex'),
      chain: [...(input.signatureChain ?? [sigBuf.toString('hex')])],
    },
  };
}

export function verifyFayingMandate(mandate, options = {}) {
  if (!mandate || mandate.protocolVersion !== '1.0' || !mandate.signature) {
    return { valid: false, errorCode: 'E_MANDATE_MALFORMED' };
  }
  const pubHex = options.trustedIssuerPublicKeyHex ?? mandate.issuerPublicKeyHex;
  const { signature, ...unsignedMandate } = mandate;
  const sigValid = verifyEd25519(
    pubHex,
    Buffer.from(canonicalizeJcs(unsignedMandate), 'utf8'),
    signature.sigHex,
  );
  if (!sigValid) {
    return { valid: false, errorCode: 'E_SIGNATURE_INVALID' };
  }
  if (mandate.grade === 'G0') {
    return { valid: false, errorCode: 'E_G0_EMERGENCY_TAKEOVER', grade: 'G0' };
  }
  if (mandate.revoked || options.revokedMandateIds?.has?.(mandate.mandateId)) {
    return { valid: false, errorCode: 'E_MANDATE_REVOKED' };
  }
  const nowEpochMs = options.nowEpochMs ?? Date.now();
  if (typeof mandate.expiresAtEpochMs !== 'number' || mandate.expiresAtEpochMs <= nowEpochMs) {
    return { valid: false, errorCode: 'E_MANDATE_EXPIRED' };
  }

  if (options.requiredResource && !mandate.scope.resources.includes(options.requiredResource)) {
    return { valid: false, errorCode: 'E_SCOPE_VIOLATION' };
  }
  if (options.requiredAction && !mandate.scope.actions.includes(options.requiredAction)) {
    return { valid: false, errorCode: 'E_SCOPE_VIOLATION' };
  }
  if (
    options.requiredDomain &&
    !mandate.scope.domains.some(
      (d) => options.requiredDomain === d || options.requiredDomain.startsWith(`${d}/`),
    )
  ) {
    return { valid: false, errorCode: 'E_SCOPE_VIOLATION' };
  }
  if (options.requiredTerminal && !mandate.scope.terminals.includes(options.requiredTerminal)) {
    return { valid: false, errorCode: 'E_SCOPE_VIOLATION' };
  }

  return {
    valid: true,
    grade: mandate.grade,
    mandateId: mandate.mandateId,
    fayId: mandate.fayId,
    humanPrimeId: mandate.humanPrimeId,
  };
}

export function delegateFayingMandate(parentMandate, request, signer) {
  const parentAutonomy = GRADE_AUTONOMY_INDEX[parentMandate.grade];
  const childAutonomy = GRADE_AUTONOMY_INDEX[request.grade];
  if (
    parentAutonomy === undefined ||
    childAutonomy === undefined ||
    childAutonomy > parentAutonomy ||
    request.grade === 'G0'
  ) {
    return {
      ok: false,
      diagnosticCode: 1099,
      errorCode: 'E_PROTOCOL',
      reason: 'Child Mandate cannot escalate autonomy grade above parent Mandate',
    };
  }

  const isSubset = (childArr = [], parentArr = []) =>
    childArr.every((item) => parentArr.includes(item));

  if (
    !isSubset(request.scope?.resources, parentMandate.scope.resources) ||
    !isSubset(request.scope?.actions, parentMandate.scope.actions) ||
    !isSubset(request.scope?.domains, parentMandate.scope.domains) ||
    !isSubset(request.scope?.terminals, parentMandate.scope.terminals) ||
    (request.deviceId && !parentMandate.scope.terminals.includes(request.deviceId))
  ) {
    return {
      ok: false,
      diagnosticCode: 1099,
      errorCode: 'E_PROTOCOL',
      reason: 'Child Mandate scope must be a strict subset of parent Mandate scope',
    };
  }

  const child = createFayingMandate(
    {
      mandateId: request.mandateId,
      humanPrimeId: parentMandate.humanPrimeId,
      fayId: request.childFayId,
      grade: request.grade,
      bindingModel: request.bindingModel ?? parentMandate.bindingModel,
      scope: request.scope,
      deviceId: request.deviceId ?? parentMandate.deviceId,
      parentMandateId: parentMandate.mandateId,
      chainDepth: (parentMandate.chainDepth ?? 0) + 1,
      issuedAtEpochMs: request.issuedAtEpochMs ?? parentMandate.issuedAtEpochMs,
      expiresAtEpochMs: Math.min(
        request.expiresAtEpochMs ?? parentMandate.expiresAtEpochMs,
        parentMandate.expiresAtEpochMs,
      ),
      signatureChain: [...(parentMandate.signature?.chain ?? []), parentMandate.signature.sigHex],
    },
    signer,
  );

  return { ok: true, value: child };
}

export function triggerG0EmergencyTakeover(activeMandate, humanPrimeSigner, nowEpochMs = Date.now()) {
  return createFayingMandate(
    {
      mandateId: `${activeMandate.mandateId}_g0_takeover`,
      humanPrimeId: activeMandate.humanPrimeId,
      fayId: activeMandate.fayId,
      grade: 'G0',
      bindingModel: activeMandate.bindingModel,
      scope: { resources: [], actions: [], domains: [], terminals: [] },
      deviceId: activeMandate.deviceId,
      parentMandateId: activeMandate.mandateId,
      issuedAtEpochMs: nowEpochMs,
      expiresAtEpochMs: activeMandate.expiresAtEpochMs,
    },
    humanPrimeSigner,
  );
}

export function toCapMandateBinding(mandate, resourceId, options = {}) {
  return {
    mandate_id: mandate.mandateId,
    fay_id: mandate.fayId,
    resource_id: resourceId,
    allowed_modes: [...(mandate.scope?.actions ?? [])],
    session_grade: mandate.grade,
    binding_model: mandate.bindingModel,
    online_fresh: options.onlineFresh ?? mandate.bindingModel !== 'model_c_offline_cache',
    revoked: Boolean(mandate.revoked),
    expires_at_epoch_ms: mandate.expiresAtEpochMs,
    ...(mandate.bindingModel === 'model_a_plus_b'
      ? { model_a_derived_proof_valid: options.modelADerivedProofValid ?? true }
      : {}),
  };
}

// ============================================================================
// 3. Authoritative FayManifest Builder, Auto-Completion, Phase & Schema Gate
// ============================================================================

export function loadFayManifestSchema() {
  if (!cachedFayManifestSchema) {
    const schemaPath = existsSync(FAYMANIFEST_SCHEMA_PATH)
      ? FAYMANIFEST_SCHEMA_PATH
      : PACKAGED_FAYMANIFEST_SCHEMA_PATH;
    cachedFayManifestSchema = JSON.parse(readFileSync(schemaPath, 'utf8'));
  }
  return cachedFayManifestSchema;
}

export function createFayManifest(input) {
  const manifest = {
    name: input.name,
    version: input.version ?? '1.0.0',
    description: input.description,
    vendor: input.vendor,
    ...(input.fayId !== undefined ? { fayId: input.fayId } : {}),
    modules: (input.modules ?? []).map((m) => (typeof m === 'string' ? { id: m } : { ...m })),
    protocols: (input.protocols ?? []).map((p) => (typeof p === 'string' ? { id: p } : { ...p })),
    controlMode: input.controlMode ?? 'command',
    ...(input.drivers !== undefined ? { drivers: structuredClone(input.drivers) } : {}),
    ...(input.ego !== undefined ? { ego: structuredClone(input.ego) } : {}),
    ...(input.permissions !== undefined ? { permissions: structuredClone(input.permissions) } : {}),
  };
  const check = validateFayManifest(manifest);
  if (!check.valid) {
    throw new Error(`Invalid FayManifest:\n${check.errors.join('\n')}`);
  }
  return manifest;
}

export function validateFayManifest(manifest) {
  const schema = loadFayManifestSchema();
  const errors = validateAgainstSchemaNode(manifest, schema, schema, '$');

  if (manifest && Array.isArray(manifest.modules)) {
    const seenModules = new Set();
    for (const [idx, item] of manifest.modules.entries()) {
      if (item && typeof item.id === 'string') {
        if (seenModules.has(item.id)) {
          errors.push(`$.modules[${idx}].id duplicate module id '${item.id}' is not allowed`);
        }
        seenModules.add(item.id);
      }
    }
  }
  if (manifest && Array.isArray(manifest.protocols)) {
    const seenProtocols = new Set();
    for (const [idx, item] of manifest.protocols.entries()) {
      if (item && typeof item.id === 'string') {
        if (seenProtocols.has(item.id)) {
          errors.push(`$.protocols[${idx}].id duplicate protocol id '${item.id}' is not allowed`);
        }
        seenProtocols.add(item.id);
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

function validateAgainstSchemaNode(value, node, rootSchema, path) {
  const resolved = node?.$ref
    ? rootSchema.$defs?.[node.$ref.replace('#/$defs/', '')]
    : node;
  if (!resolved) return [`${path} unresolvable schema ref ${node?.$ref}`];

  const errors = [];
  if (resolved.type === 'object') {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return [`${path} must be object`];
    }
    for (const reqKey of resolved.required ?? []) {
      if (!(reqKey in value)) {
        errors.push(`${path}.${reqKey} is required`);
      }
    }
    const props = resolved.properties ?? {};
    if (resolved.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!(key in props)) {
          errors.push(`${path}.${key} is not allowed`);
        }
      }
    }
    for (const [key, propSchema] of Object.entries(props)) {
      if (key in value && value[key] !== undefined) {
        errors.push(...validateAgainstSchemaNode(value[key], propSchema, rootSchema, `${path}.${key}`));
      }
    }
    return errors;
  }

  if (resolved.type === 'array') {
    if (!Array.isArray(value)) return [`${path} must be array`];
    for (const [idx, elem] of value.entries()) {
      errors.push(...validateAgainstSchemaNode(elem, resolved.items, rootSchema, `${path}[${idx}]`));
    }
    return errors;
  }

  if (resolved.type === 'string') {
    if (typeof value !== 'string') return [`${path} must be string`];
    if (resolved.minLength !== undefined && value.length < resolved.minLength) {
      errors.push(`${path} must have length >= ${resolved.minLength}`);
    }
    if (resolved.pattern && !new RegExp(resolved.pattern).test(value)) {
      errors.push(`${path} must match ${resolved.pattern}`);
    }
    if (resolved.enum && !resolved.enum.includes(value)) {
      errors.push(`${path} must be one of ${resolved.enum.join(', ')}`);
    }
  }

  return errors;
}

export function classifyPackageNamespace(packageId) {
  if (
    typeof packageId !== 'string' ||
    !/^@[a-z0-9]([a-z0-9-]*[a-z0-9])?\/[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/.test(packageId)
  ) {
    return 'invalid';
  }
  const scope = packageId.split('/')[0];
  return GOVERNED_PACKAGE_SCOPES.includes(scope) ? 'governed' : 'ungoverned';
}

export function resolveFayManifestDependencies(manifest) {
  const declaredModules = (manifest.modules ?? []).map((m) => m.id);
  const declaredProtocols = (manifest.protocols ?? []).map((p) => p.id);

  const moduleSet = new Set([...declaredModules, ...CORE_INFRASTRUCTURE_MODULES]);
  if (manifest.ego) {
    moduleSet.add('ego_model');
  }
  const protocolSet = new Set([...declaredProtocols, 'faying_protocol']);

  const driverNamespaces = (manifest.drivers ?? []).map((d) => ({
    driverPackage: d.driverPackage,
    governance: classifyPackageNamespace(d.driverPackage),
  }));
  const egoNamespace = manifest.ego?.modelSource
    ? classifyPackageNamespace(manifest.ego.modelSource)
    : null;

  return {
    modules: Array.from(moduleSet),
    protocols: Array.from(protocolSet),
    autoCompletedModules: Array.from(moduleSet).filter((m) => !declaredModules.includes(m)),
    autoCompletedProtocols: Array.from(protocolSet).filter((p) => !declaredProtocols.includes(p)),
    driverNamespaces,
    egoNamespace,
  };
}

const PHASE_INDICATORS = [
  {
    phaseNumber: 5,
    phase: 'Phase 5',
    modules: new Set(['gmchain', 'meritoken']),
    protocols: new Set([]),
  },
  {
    phaseNumber: 4,
    phase: 'Phase 4',
    modules: new Set(['self_awareness', 'self_driven_behavior', 'internal_skill', 'aligned_consciousness']),
    protocols: new Set(['telepathy_protocol']),
  },
  {
    phaseNumber: 3,
    phase: 'Phase 3',
    modules: new Set(['external_knowledge']),
    protocols: new Set(['ssp_protocol']),
  },
  {
    phaseNumber: 2,
    phase: 'Phase 2',
    modules: new Set(['sensor', 'device_driver_hub', 'registered_skill', 'invoke_skill', 'personal_data_heap']),
    protocols: new Set(['cap_protocol', 'dtp_protocol']),
  },
];

export function classifyFayManifestPhase(manifest) {
  const modIds = new Set((manifest.modules ?? []).map((m) => m.id));
  const protoIds = new Set((manifest.protocols ?? []).map((p) => p.id));

  if (manifest.controlMode === 'autonomous') {
    for (const entry of PHASE_INDICATORS) {
      if (
        entry.phaseNumber >= 4 &&
        ([...modIds].some((m) => entry.modules.has(m)) ||
          [...protoIds].some((p) => entry.protocols.has(p)))
      ) {
        return {
          phase: entry.phase,
          phaseNumber: entry.phaseNumber,
          requiredStages: Array.from({ length: entry.phaseNumber }, (_, i) => `Phase ${i + 1}`),
        };
      }
    }
    return {
      phase: 'Phase 4',
      phaseNumber: 4,
      requiredStages: ['Phase 1', 'Phase 2', 'Phase 3', 'Phase 4'],
    };
  }

  for (const entry of PHASE_INDICATORS) {
    const matched =
      [...modIds].some((m) => entry.modules.has(m)) ||
      [...protoIds].some((p) => entry.protocols.has(p)) ||
      (entry.phaseNumber === 2 && Array.isArray(manifest.drivers) && manifest.drivers.length > 0);
    if (matched) {
      return {
        phase: entry.phase,
        phaseNumber: entry.phaseNumber,
        requiredStages: Array.from({ length: entry.phaseNumber }, (_, i) => `Phase ${i + 1}`),
      };
    }
  }

  return {
    phase: 'Phase 1',
    phaseNumber: 1,
    requiredStages: ['Phase 1'],
  };
}

// ============================================================================
// 4. CAP 1.0 Safety Gate (D-1..D-7) & Driver Capability Manifest Helpers
// ============================================================================

const CAP_DIAGNOSTIC_CODES = Object.freeze({
  E_WEAK_MANDATE_BINDING: 2001,
  E_GRADE_INSUFFICIENT: 2002,
  E_G0_EMERGENCY_OVERRIDE: 2003,
  E_UNKNOWN_OPERATION: 2004,
  E_UNTRUSTED_MANIFEST: 2005,
  E_CONFIRMATION_REQUIRED: 2006,
  E_OUT_OF_SCOPE_FUND_TRANSFER: 2007,
  E_MANDATE_INVALID: 2008,
  E_PROTOCOL_VERSION_UNSUPPORTED: 2009,
});

const CRITICALITY_ORDER = Object.freeze({
  routine: 0,
  sensitive: 1,
  high: 2,
  critical: 3,
});

const GRADE_STRENGTH = Object.freeze({
  G1: 4,
  G2: 3,
  G3: 2,
  G4: 1,
});

export function computeCapParamsSha256(params) {
  return createHash('sha256')
    .update(canonicalizeJcs(params ?? {}), 'utf8')
    .digest('hex');
}

export function signCapDriverManifest(unsignedManifest, seed32) {
  const { signature_ed25519: _ignored, ...payload } = unsignedManifest;
  const sig = signEd25519(seed32, Buffer.from(canonicalizeJcs(payload), 'utf8'));
  return {
    ...payload,
    signature_ed25519: sig.toString('hex'),
  };
}

export function verifyCapDriverManifest(manifest, trustAnchors) {
  if (!manifest?.signature_ed25519 || !/^[0-9a-f]{128}$/i.test(manifest.signature_ed25519)) {
    return false;
  }
  const anchor = trustAnchors?.[manifest.signer_key_id];
  if (!anchor || anchor.algorithm !== 'Ed25519' || !/^[0-9a-f]{64}$/i.test(anchor.public_key_raw_hex)) {
    return false;
  }
  const { signature_ed25519: _sig, ...unsignedPayload } = manifest;
  return verifyEd25519(
    anchor.public_key_raw_hex,
    Buffer.from(canonicalizeJcs(unsignedPayload), 'utf8'),
    manifest.signature_ed25519,
  );
}

function isCapGradeMatrixAllowed(grade, mode, criticality) {
  if (criticality === 'critical') return grade === 'G1';
  if (criticality === 'high') return grade === 'G1' || grade === 'G2';
  if (criticality === 'sensitive') {
    if (grade === 'G1' || grade === 'G2') return true;
    if (grade === 'G3') return mode !== 'configure';
    return false;
  }
  if (grade === 'G1' || grade === 'G2' || grade === 'G3') return true;
  return mode === 'read' || mode === 'execute';
}

function capDeny(code, effectiveCriticality, escalationClamped, reason, extra = {}) {
  return {
    decision: 'DENY',
    effective_criticality: effectiveCriticality,
    escalation_clamped: escalationClamped,
    error_code: code,
    diagnostic_code: CAP_DIAGNOSTIC_CODES[code],
    reason,
    ...extra,
  };
}

export function evaluateCapAction(req, trustAnchors) {
  if (req.protocol_version !== '1.0') {
    return capDeny(
      'E_PROTOCOL_VERSION_UNSUPPORTED',
      'critical',
      false,
      `Unsupported CAP protocol_version: ${req.protocol_version}`,
    );
  }
  if (req.domain_category === 'fund_transfer') {
    return capDeny(
      'E_OUT_OF_SCOPE_FUND_TRANSFER',
      'critical',
      false,
      'Financial fund_transfer operations are excluded from CAP 1.0 scope',
    );
  }
  if (!verifyCapDriverManifest(req.manifest, trustAnchors)) {
    return capDeny(
      'E_UNTRUSTED_MANIFEST',
      'critical',
      false,
      'DriverCapabilityManifest failed Ed25519 signature or trust anchor verification',
    );
  }

  const resource = req.manifest.resources?.find((r) => r.resource_id === req.resource_id);
  const operation = resource?.operations?.find((op) => op.operation_id === req.operation_id);
  if (!resource || !operation) {
    return capDeny(
      'E_UNKNOWN_OPERATION',
      'critical',
      false,
      `Undeclared resource/operation ${req.resource_id}/${req.operation_id} defaults to critical DENY`,
    );
  }
  if (operation.domain_category === 'fund_transfer') {
    return capDeny(
      'E_OUT_OF_SCOPE_FUND_TRANSFER',
      'critical',
      false,
      'Manifest-declared fund_transfer operation is excluded from CAP 1.0 scope',
    );
  }

  let floorCriticality = operation.criticality;
  if (operation.consequence_irreversibility === 'irreversible_data_or_hardware') {
    floorCriticality = 'critical';
  } else if (
    operation.consequence_irreversibility === 'irreversible_consequence' &&
    CRITICALITY_ORDER[floorCriticality] < CRITICALITY_ORDER.high
  ) {
    floorCriticality = 'high';
  }

  let effectiveCriticality = floorCriticality;
  let escalationClamped = false;
  for (const override of [req.grant?.criticality_override, req.caller_criticality_override]) {
    if (override !== undefined) {
      if (CRITICALITY_ORDER[override] < CRITICALITY_ORDER[floorCriticality]) {
        escalationClamped = true;
      } else if (CRITICALITY_ORDER[override] > CRITICALITY_ORDER[effectiveCriticality]) {
        effectiveCriticality = override;
      }
    }
  }

  const mandate = req.grant?.mandate_binding;
  const sessionGrade = mandate?.session_grade;
  if (req.g0_override === true || sessionGrade === 'G0') {
    const primarySafeState = resource.safe_states?.[0]?.safe_state_id;
    return capDeny(
      'E_G0_EMERGENCY_OVERRIDE',
      effectiveCriticality,
      escalationClamped,
      'Human Prime G0 emergency takeover active',
      {
        safe_state_directive: primarySafeState
          ? {
              action: 'enter_safe_state',
              safe_state_id: primarySafeState,
              blocks_human_takeover: false,
            }
          : {
              action: 'terminate_and_alert',
              blocks_human_takeover: false,
            },
      },
    );
  }

  if (
    !mandate ||
    mandate.revoked ||
    mandate.expires_at_epoch_ms <= req.now_epoch_ms ||
    mandate.fay_id !== req.fay_id ||
    mandate.resource_id !== req.resource_id ||
    req.grant.resource_id !== req.resource_id ||
    operation.mode !== req.requested_mode ||
    !req.grant.allowed_modes.includes(req.requested_mode) ||
    !mandate.allowed_modes.includes(req.requested_mode)
  ) {
    return capDeny(
      'E_MANDATE_INVALID',
      effectiveCriticality,
      escalationClamped,
      'Mandate or grant expired, revoked, or mismatched with subject/resource/mode',
    );
  }

  const isHighOrCritical =
    effectiveCriticality === 'high' || effectiveCriticality === 'critical';

  if (isHighOrCritical) {
    if (
      mandate.binding_model !== 'model_a_plus_b' ||
      !mandate.online_fresh ||
      mandate.model_a_derived_proof_valid !== true
    ) {
      return capDeny(
        'E_WEAK_MANDATE_BINDING',
        effectiveCriticality,
        escalationClamped,
        'High and critical operations require Model A+B cryptographic session binding and online freshness',
      );
    }
  } else if (
    mandate.binding_model === 'model_b_online_ref' ||
    mandate.binding_model === 'model_a_plus_b'
  ) {
    if (!mandate.online_fresh) {
      return capDeny(
        'E_MANDATE_INVALID',
        effectiveCriticality,
        escalationClamped,
        'Online Mandate binding model requires online_fresh == true',
      );
    }
  } else if (
    effectiveCriticality === 'sensitive' &&
    mandate.binding_model === 'model_c_offline_cache'
  ) {
    return capDeny(
      'E_WEAK_MANDATE_BINDING',
      effectiveCriticality,
      escalationClamped,
      'Sensitive operations require online Mandate verification (Model B or Model A+B)',
    );
  }

  if (
    GRADE_STRENGTH[sessionGrade] < GRADE_STRENGTH[req.grant.min_grade] ||
    !isCapGradeMatrixAllowed(sessionGrade, req.requested_mode, effectiveCriticality)
  ) {
    return capDeny(
      'E_GRADE_INSUFFICIENT',
      effectiveCriticality,
      escalationClamped,
      `Session grade ${sessionGrade} and mode ${req.requested_mode} insufficient for ${effectiveCriticality}`,
    );
  }

  if (isHighOrCritical) {
    const confirmation = req.human_confirmation;
    const expectedHash = computeCapParamsSha256(req.params);
    if (
      !confirmation ||
      !/^hid_[a-z2-7]{16,}$/.test(confirmation.human_prime_id) ||
      confirmation.expires_at_epoch_ms <= req.now_epoch_ms ||
      confirmation.terminal_attested_disclosure !== true ||
      confirmation.confirmed_params_sha256 !== expectedHash
    ) {
      return capDeny(
        'E_CONFIRMATION_REQUIRED',
        effectiveCriticality,
        escalationClamped,
        'High and critical operations require unexpired, terminal-attested, parameter-bound Human Prime confirmation',
      );
    }
  }

  return {
    decision: 'ALLOW',
    effective_criticality: effectiveCriticality,
    effective_grade: sessionGrade,
    escalation_clamped: escalationClamped,
  };
}

// ============================================================================
// 5. SSP 1.0 Detached Ed25519 JWS SkillProof Helpers
// ============================================================================

function base64UrlEncode(buf) {
  return Buffer.from(buf).toString('base64url');
}

function base64UrlDecode(str) {
  return Buffer.from(str, 'base64url');
}

export function isSspVersionCompatible(descriptorVersion, consumerVersion = '1.0') {
  const twoSegRe = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
  if (!twoSegRe.test(descriptorVersion) || !twoSegRe.test(consumerVersion)) {
    return false;
  }
  return descriptorVersion.split('.')[0] === consumerVersion.split('.')[0];
}

export function signSkillDescriptor(descriptor, options) {
  const { proof: _oldProof, ...unsignedDescriptor } = descriptor;
  const parsedPub = parseFayId(unsignedDescriptor.publisherFayId);
  if (
    !parsedPub.ok ||
    (parsedPub.value.kind !== 'IFAY_ID' && parsedPub.value.kind !== 'COFAY_ID')
  ) {
    throw new Error('publisherFayId must be a canonical ifay_ or cofay_ identifier');
  }
  if (!isSspVersionCompatible(unsignedDescriptor.version ?? '1.0', '1.0')) {
    throw new Error(`Invalid two-segment SSP 1.0 version: ${unsignedDescriptor.version}`);
  }

  const kid = options.kid ?? `${parsedPub.value.value}#ssp-1`;
  const created = options.created ?? '2026-11-16T00:00:00Z';
  const protectedHeader = {
    alg: 'EdDSA',
    kid,
    typ: 'ssp-descriptor+jcs',
  };
  const encodedHeader = base64UrlEncode(Buffer.from(canonicalizeJcs(protectedHeader), 'utf8'));
  const jcsPayloadBytes = Buffer.from(canonicalizeJcs(unsignedDescriptor), 'utf8');
  const signingInput = Buffer.concat([
    Buffer.from(`${encodedHeader}.`, 'ascii'),
    jcsPayloadBytes,
  ]);
  const sigBytes = options.signer.signPayload(signingInput);
  const detachedJws = `${encodedHeader}..${base64UrlEncode(sigBytes)}`;

  return {
    ...unsignedDescriptor,
    proof: {
      type: 'Ed25519JcsDetachedJws2025',
      alg: 'EdDSA',
      kid,
      created,
      jws: detachedJws,
    },
  };
}

export function verifySkillDescriptor(signedDescriptor, options = {}) {
  try {
    if (!signedDescriptor || typeof signedDescriptor !== 'object' || !signedDescriptor.proof) {
      return { valid: false, errorCode: 'SSP_PROOF_MISSING' };
    }
    const { proof, ...unsignedDescriptor } = signedDescriptor;
    if (!isSspVersionCompatible(unsignedDescriptor.version, options.consumerVersion ?? '1.0')) {
      return { valid: false, errorCode: 'SSP_VERSION_INCOMPATIBLE' };
    }
    const parsedPub = parseFayId(unsignedDescriptor.publisherFayId);
    if (
      !parsedPub.ok ||
      (parsedPub.value.kind !== 'IFAY_ID' && parsedPub.value.kind !== 'COFAY_ID')
    ) {
      return { valid: false, errorCode: 'SSP_PUBLISHER_ID_INVALID' };
    }
    if (
      (unsignedDescriptor.visibility === 'private' ||
        unsignedDescriptor.visibility === 'restricted') &&
      options.requireAuthForRestricted &&
      !isValidFayId(options.callerFayId)
    ) {
      return { valid: false, errorCode: 'SSP_VISIBILITY_AUTH_REQUIRED' };
    }
    if (proof.alg !== 'EdDSA' || typeof proof.jws !== 'string') {
      return { valid: false, errorCode: 'SSP_UNSUPPORTED_ALG' };
    }
    const parts = proof.jws.split('.');
    if (parts.length !== 3 || parts[1] !== '') {
      return { valid: false, errorCode: 'SSP_MALFORMED_DETACHED_JWS' };
    }
    const [encodedHeader, , encodedSig] = parts;
    const headerObj = JSON.parse(base64UrlDecode(encodedHeader).toString('utf8'));
    if (headerObj.alg !== 'EdDSA') {
      return { valid: false, errorCode: 'SSP_UNSUPPORTED_ALG' };
    }
    const jcsPayloadBytes = Buffer.from(canonicalizeJcs(unsignedDescriptor), 'utf8');
    const signingInput = Buffer.concat([
      Buffer.from(`${encodedHeader}.`, 'ascii'),
      jcsPayloadBytes,
    ]);
    const okSig = verifyEd25519(
      options.trustedPublicKeyHex,
      signingInput,
      base64UrlDecode(encodedSig),
    );
    return okSig
      ? { valid: true, publisherFayId: parsedPub.value.value, kid: proof.kid }
      : { valid: false, errorCode: 'SSP_SIGNATURE_INVALID' };
  } catch {
    return { valid: false, errorCode: 'SSP_VERIFICATION_ERROR' };
  }
}

// ============================================================================
// 6. DTP 1.0 Wire Codec & Ego Vault Two-Tier Integrity + Privacy Helpers
// ============================================================================

const DTP_KNOWN_HEADER_KEYS = [
  'protocolVersion',
  'frameType',
  'fragmentId',
  'agreementId',
  'originTimestamp',
  'dagDependencies',
  'encryptionMetadata',
  'sequenceNumber',
];

export function encodeDtpFrame(header, plaintextBytes, sessionKeyBytes, ivBytes) {
  const key = Buffer.from(sessionKeyBytes);
  const iv = Buffer.from(ivBytes);
  if (key.length !== 32 || iv.length !== 12) {
    throw new RangeError('DTP AES-256-GCM requires 32-byte sessionKey and 12-byte IV');
  }
  const jcsHeaderStr = canonicalizeJcs(header);
  const headerBuf = Buffer.from(jcsHeaderStr, 'utf8');
  const lenPrefix = Buffer.alloc(4);
  lenPrefix.writeUInt32BE(headerBuf.length, 0);

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintextBytes)), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const encryptedPayload = Buffer.concat([iv, ciphertext, authTag]);

  return {
    jcsHeader: jcsHeaderStr,
    encryptedPayload,
    wireFrame: Buffer.concat([lenPrefix, headerBuf, encryptedPayload]),
  };
}

export function decodeDtpFrame(wireFrameBytes, sessionKeyBytes) {
  const wire = Buffer.from(wireFrameBytes);
  const key = Buffer.from(sessionKeyBytes);
  if (wire.length < 4) {
    return { ok: false, errorCode: 1001, errorName: 'FRAME_DESERIALIZATION_FAILED' };
  }
  const headerLen = wire.readUInt32BE(0);
  if (headerLen === 0 || 4 + headerLen > wire.length) {
    return { ok: false, errorCode: 1001, errorName: 'FRAME_DESERIALIZATION_FAILED' };
  }
  let rawHeader;
  try {
    rawHeader = JSON.parse(wire.subarray(4, 4 + headerLen).toString('utf8'));
  } catch {
    return { ok: false, errorCode: 1001, errorName: 'FRAME_DESERIALIZATION_FAILED' };
  }
  if (
    !rawHeader ||
    typeof rawHeader !== 'object' ||
    !rawHeader.protocolVersion ||
    typeof rawHeader.protocolVersion.major !== 'number' ||
    typeof rawHeader.protocolVersion.minor !== 'number' ||
    typeof rawHeader.frameType !== 'string' ||
    typeof rawHeader.fragmentId !== 'string' ||
    !(typeof rawHeader.agreementId === 'string' || rawHeader.agreementId === null) ||
    typeof rawHeader.originTimestamp !== 'number' ||
    !Array.isArray(rawHeader.dagDependencies) ||
    !rawHeader.encryptionMetadata ||
    typeof rawHeader.sequenceNumber !== 'number'
  ) {
    return { ok: false, errorCode: 1001, errorName: 'FRAME_DESERIALIZATION_FAILED' };
  }
  if (rawHeader.protocolVersion.major !== 1) {
    return { ok: false, errorCode: 7001, errorName: 'VERSION_INCOMPATIBLE' };
  }

  const encPayload = wire.subarray(4 + headerLen);
  if (encPayload.length < 28 || key.length !== 32) {
    return { ok: false, errorCode: 2001, errorName: 'DECRYPTION_FAILED' };
  }
  const iv = encPayload.subarray(0, 12);
  const authTag = encPayload.subarray(encPayload.length - 16);
  const ciphertext = encPayload.subarray(12, encPayload.length - 16);

  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const projectedHeader = {};
    for (const k of DTP_KNOWN_HEADER_KEYS) {
      projectedHeader[k] = rawHeader[k];
    }
    return {
      ok: true,
      header: projectedHeader,
      rawHeader,
      plaintext,
    };
  } catch {
    return { ok: false, errorCode: 2001, errorName: 'DECRYPTION_FAILED' };
  }
}

export function deriveEgoVaultSubkeySeed(masterSeed) {
  const buf = Buffer.from(masterSeed);
  if (buf.length !== 32) {
    throw new RangeError('masterSeed must be 32 bytes');
  }
  return Buffer.from(
    hkdfSync(
      'sha256',
      buf,
      Buffer.from('ifay.fayid.hkdf.v1', 'ascii'),
      Buffer.from(SUBKEY_DOMAINS.EGO_PACKAGE_SIGNING, 'ascii'),
      32,
    ),
  );
}

export function signEgoVaultManifest(manifest, { masterSeed, signerFayId, keyId }) {
  const parsed = parseFayId(signerFayId);
  if (!parsed.ok || parsed.value.kind !== 'IFAY_ID') {
    throw new Error(`signerFayId must start with ifay_, got ${signerFayId}`);
  }
  const subSeed = deriveEgoVaultSubkeySeed(masterSeed);
  const kp = ed25519KeypairFromSeed(subSeed);
  subSeed.fill(0);

  const { signature: _old, ...payloadObj } = manifest;
  const jcsBytes = Buffer.from(canonicalizeJcs(payloadObj), 'utf8');
  const payloadJcsSha256 = createHash('sha256').update(jcsBytes).digest('hex');
  const signingMsg = Buffer.concat([
    Buffer.from(`${SUBKEY_DOMAINS.EGO_PACKAGE_SIGNING}:`, 'ascii'),
    jcsBytes,
  ]);
  const sigHex = kp.signPayload(signingMsg).toString('hex');

  return {
    ...payloadObj,
    signature: {
      schema_version: '1.0',
      alg: 'Ed25519',
      domain: SUBKEY_DOMAINS.EGO_PACKAGE_SIGNING,
      signer_fay_id: parsed.value.value,
      key_id: keyId ?? `${parsed.value.value}#ego-sign-1`,
      public_key_hex: kp.publicKeyHex,
      payload_jcs_sha256: payloadJcsSha256,
      sig_hex: sigHex,
    },
  };
}

export function verifyEgoVaultManifest(manifest, options = {}) {
  if (!manifest || typeof manifest !== 'object' || !manifest.signature || !manifest.integrity) {
    return { valid: false, errorCode: 'EGO_SIGNATURE_OR_INTEGRITY_MISSING' };
  }
  const { signature, ...payloadObj } = manifest;
  if (
    signature.schema_version !== '1.0' ||
    signature.alg !== 'Ed25519' ||
    signature.domain !== SUBKEY_DOMAINS.EGO_PACKAGE_SIGNING ||
    !isValidFayId(signature.signer_fay_id, 'IFAY_ID')
  ) {
    return { valid: false, errorCode: 'EGO_SIGNATURE_ENVELOPE_INVALID' };
  }
  if (
    options.trustedPublicKeyHex &&
    signature.public_key_hex.toLowerCase() !== options.trustedPublicKeyHex.toLowerCase()
  ) {
    return { valid: false, errorCode: 'EGO_UNTRUSTED_SIGNER_KEY' };
  }
  const jcsBytes = Buffer.from(canonicalizeJcs(payloadObj), 'utf8');
  const actualSha = createHash('sha256').update(jcsBytes).digest('hex');
  if (actualSha !== signature.payload_jcs_sha256) {
    return { valid: false, errorCode: 'EGO_PAYLOAD_DIGEST_MISMATCH' };
  }
  const signingMsg = Buffer.concat([
    Buffer.from(`${SUBKEY_DOMAINS.EGO_PACKAGE_SIGNING}:`, 'ascii'),
    jcsBytes,
  ]);
  if (!verifyEd25519(signature.public_key_hex, signingMsg, signature.sig_hex)) {
    return { valid: false, errorCode: 'EGO_SIGNATURE_INVALID' };
  }
  if (manifest.fidelity_report !== undefined) {
    const priv = validateEgoFidelityPrivacy(manifest.fidelity_report);
    if (!priv.valid) {
      return { valid: false, errorCode: priv.errorCode };
    }
  }
  return {
    valid: true,
    signerFayId: signature.signer_fay_id,
    publicKeyHex: signature.public_key_hex,
    payloadJcsSha256: actualSha,
  };
}

const ALLOWED_FIDELITY_KEYS = new Set([
  'schema_version',
  'status',
  'holdout_sample_count',
  'holdout_loss',
  'holdout_perplexity',
  'cell_consistency_score',
  'probe_win_rate',
  'drift_from_baseline',
]);

export function validateEgoFidelityPrivacy(fidelityReport) {
  if (!fidelityReport || typeof fidelityReport !== 'object' || Array.isArray(fidelityReport)) {
    return { valid: false, errorCode: 'EGO_FIDELITY_REPORT_INVALID' };
  }
  const keys = Object.keys(fidelityReport);
  for (const key of keys) {
    if (!ALLOWED_FIDELITY_KEYS.has(key)) {
      return { valid: false, errorCode: 'EGO_PRIVACY_RAW_FIELD_FORBIDDEN' };
    }
  }
  for (const reqKey of ALLOWED_FIDELITY_KEYS) {
    if (!(reqKey in fidelityReport)) {
      return { valid: false, errorCode: 'EGO_FIDELITY_REPORT_INCOMPLETE' };
    }
  }
  if (
    fidelityReport.schema_version !== '1.0' ||
    (fidelityReport.status !== 'measured' && fidelityReport.status !== 'insufficient_data')
  ) {
    return { valid: false, errorCode: 'EGO_FIDELITY_REPORT_INVALID' };
  }
  for (const numKey of [
    'holdout_sample_count',
    'holdout_loss',
    'holdout_perplexity',
    'cell_consistency_score',
    'probe_win_rate',
    'drift_from_baseline',
  ]) {
    const v = fidelityReport[numKey];
    if (v !== null && typeof v !== 'number') {
      return { valid: false, errorCode: 'EGO_PRIVACY_NON_SCALAR_VALUE' };
    }
  }
  return { valid: true };
}
