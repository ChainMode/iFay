import { createHash } from 'node:crypto';
import { signEd25519, verifyEd25519 } from '@ifay/sdk';

export const BUF_MAGIC = Buffer.freeze ? Buffer.from('BUF\0', 'ascii') : Buffer.from('BUF\0', 'ascii');
export const BUF_HEADER_SIZE = 40;
export const BUF_TRAILER_SIZE = 44;
export const BUF_FORMAT_VERSION_M0 = 1;
export const BUF_MANIFEST_DIGEST_SIZE = 32;
export const BUF_SIG_ALG_ED25519 = 'ed25519';

const KNOWN_MANIFEST_FIELDS = new Set([
  'schema_version',
  'runtime_interface_min',
  'deprecation_notice',
  'entry',
  'runtime',
  'capabilities',
  'quotas',
  'sections',
  'signature',
]);

const SECTION_KIND_UNITS = new Set(['code', 'data', 'asset', 'signature']);
const SECTION_VISIBILITIES = new Set(['required', 'optional']);
const SELECTION_STRATEGIES = new Set(['strict', 'prefer_then_any', 'any']);

const CBOR_BYTES_BRAND = Symbol.for('ifay.soul.cborBytes');

// Precomputed IEEE 802.3 CRC-32 table (polynomial 0xEDB88320)
const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

export function crc32Ieee(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    crc = CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function sha256Bytes(input) {
  return createHash('sha256').update(input).digest();
}

export function sha256Hex(input) {
  return createHash('sha256').update(input).digest('hex');
}

export function cborBytes(bytes) {
  return Object.freeze({
    [CBOR_BYTES_BRAND]: true,
    bytes: Buffer.from(bytes),
  });
}

export function isCborBytes(val) {
  return Boolean(val && typeof val === 'object' && val[CBOR_BYTES_BRAND] === true);
}

// ============================================================================
// SemVer Validator (matching fayger-buf/src/manifest/semver.rs)
// ============================================================================

export function isValidBufSemVer(version) {
  if (typeof version !== 'string' || version.length === 0 || version.includes('+')) {
    return false;
  }
  const dashIdx = version.indexOf('-');
  const core = dashIdx === -1 ? version : version.slice(0, dashIdx);
  const pre = dashIdx === -1 ? null : version.slice(dashIdx + 1);

  const parts = core.split('.');
  if (parts.length !== 3) return false;
  for (const part of parts) {
    if (part.length === 0) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    if (!/^[0-9]+$/.test(part)) return false;
    const n = Number(part);
    if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) return false;
  }
  if (pre !== null) {
    if (pre.length === 0 || !/^[A-Za-z0-9.-]+$/.test(pre)) return false;
  }
  return true;
}

// ============================================================================
// Canonical CBOR Codec (RFC 8949 §4.2, matching fayger-buf/src/canonical.rs)
// ============================================================================

const U64_MAX = 0xffffffffffffffffn;

function writeCborHead(major, valueBigInt, chunks) {
  if (valueBigInt < 0n || valueBigInt > U64_MAX) {
    throw new RangeError(`CBOR unsigned argument out of u64 range: ${valueBigInt}`);
  }
  const initial = (major << 5) & 0xe0;
  if (valueBigInt <= 23n) {
    chunks.push(Buffer.from([initial | Number(valueBigInt)]));
  } else if (valueBigInt <= 0xffn) {
    chunks.push(Buffer.from([initial | 0x18, Number(valueBigInt)]));
  } else if (valueBigInt <= 0xffffn) {
    const b = Buffer.allocUnsafe(3);
    b[0] = initial | 0x19;
    b.writeUInt16BE(Number(valueBigInt), 1);
    chunks.push(b);
  } else if (valueBigInt <= 0xffffffffn) {
    const b = Buffer.allocUnsafe(5);
    b[0] = initial | 0x1a;
    b.writeUInt32BE(Number(valueBigInt), 1);
    chunks.push(b);
  } else {
    const b = Buffer.allocUnsafe(9);
    b[0] = initial | 0x1b;
    b.writeBigUInt64BE(valueBigInt, 1);
    chunks.push(b);
  }
}

function writeCanonicalValue(value, chunks) {
  if (value === null) {
    chunks.push(Buffer.from([0xf6]));
    return;
  }
  if (typeof value === 'boolean') {
    chunks.push(Buffer.from([value ? 0xf5 : 0xf4]));
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isInteger(value)) {
      throw new TypeError('BuF canonical CBOR rejects floating-point numbers');
    }
    if (!Number.isSafeInteger(value)) {
      throw new RangeError('Unsafe integer in CBOR encode; pass BigInt instead');
    }
    writeCanonicalInteger(BigInt(value), chunks);
    return;
  }
  if (typeof value === 'bigint') {
    writeCanonicalInteger(value, chunks);
    return;
  }
  if (typeof value === 'string') {
    const utf8 = Buffer.from(value, 'utf8');
    writeCborHead(3, BigInt(utf8.length), chunks);
    if (utf8.length > 0) chunks.push(utf8);
    return;
  }
  if (isCborBytes(value)) {
    const raw = value.bytes;
    writeCborHead(2, BigInt(raw.length), chunks);
    if (raw.length > 0) chunks.push(raw);
    return;
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const raw = Buffer.from(value);
    writeCborHead(2, BigInt(raw.length), chunks);
    if (raw.length > 0) chunks.push(raw);
    return;
  }
  if (Array.isArray(value)) {
    writeCborHead(4, BigInt(value.length), chunks);
    for (const item of value) {
      writeCanonicalValue(item, chunks);
    }
    return;
  }
  if (value instanceof Map) {
    const encodedEntries = [];
    for (const [k, v] of value.entries()) {
      if (v === undefined) continue;
      const kb = encodeCanonicalCbor(k);
      const vb = encodeCanonicalCbor(v);
      encodedEntries.push([kb, vb]);
    }
    writeSortedMapEntries(encodedEntries, chunks);
    return;
  }
  if (typeof value === 'object') {
    const encodedEntries = [];
    for (const k of Object.keys(value)) {
      const v = value[k];
      if (v === undefined) continue;
      const kb = encodeCanonicalCbor(k);
      const vb = encodeCanonicalCbor(v);
      encodedEntries.push([kb, vb]);
    }
    writeSortedMapEntries(encodedEntries, chunks);
    return;
  }
  throw new TypeError(`Unsupported value type in BuF canonical CBOR: ${typeof value}`);
}

function writeCanonicalInteger(n, chunks) {
  if (n >= 0n) {
    if (n > U64_MAX) {
      throw new RangeError(`Unsigned integer exceeds u64::MAX: ${n}`);
    }
    writeCborHead(0, n, chunks);
  } else {
    const v = -1n - n;
    if (v < 0n || v > U64_MAX) {
      throw new RangeError(`Negative integer exceeds CBOR major-1 u64 range: ${n}`);
    }
    writeCborHead(1, v, chunks);
  }
}

function writeSortedMapEntries(encodedEntries, chunks) {
  encodedEntries.sort((a, b) => Buffer.compare(a[0], b[0]));
  for (let i = 1; i < encodedEntries.length; i += 1) {
    if (Buffer.compare(encodedEntries[i - 1][0], encodedEntries[i][0]) === 0) {
      throw new Error('Duplicate map key in BuF canonical CBOR');
    }
  }
  writeCborHead(5, BigInt(encodedEntries.length), chunks);
  for (const [kb, vb] of encodedEntries) {
    chunks.push(kb, vb);
  }
}

export function encodeCanonicalCbor(value) {
  const chunks = [];
  writeCanonicalValue(value, chunks);
  return Buffer.concat(chunks);
}

function readCborArg(buf, offset, info) {
  if (info <= 23) {
    return { value: BigInt(info), nextOffset: offset };
  }
  if (info === 24) {
    if (offset + 1 > buf.length) throw new Error('Truncated CBOR 1-byte uint');
    const v = BigInt(buf[offset]);
    if (v <= 23n) throw new Error('Non-canonical CBOR: IntegerNotShortest');
    return { value: v, nextOffset: offset + 1 };
  }
  if (info === 25) {
    if (offset + 2 > buf.length) throw new Error('Truncated CBOR 2-byte uint');
    const v = BigInt(buf.readUInt16BE(offset));
    if (v <= 0xffn) throw new Error('Non-canonical CBOR: IntegerNotShortest');
    return { value: v, nextOffset: offset + 2 };
  }
  if (info === 26) {
    if (offset + 4 > buf.length) throw new Error('Truncated CBOR 4-byte uint');
    const v = BigInt(buf.readUInt32BE(offset));
    if (v <= 0xffffn) throw new Error('Non-canonical CBOR: IntegerNotShortest');
    return { value: v, nextOffset: offset + 4 };
  }
  if (info === 27) {
    if (offset + 8 > buf.length) throw new Error('Truncated CBOR 8-byte uint');
    const v = buf.readBigUInt64BE(offset);
    if (v <= 0xffffffffn) throw new Error('Non-canonical CBOR: IntegerNotShortest');
    return { value: v, nextOffset: offset + 8 };
  }
  if (info === 31) {
    throw new Error('Non-canonical CBOR: IndefiniteLength');
  }
  throw new Error(`Invalid CBOR additional info: ${info}`);
}

function toJsInteger(bigVal) {
  if (bigVal >= BigInt(Number.MIN_SAFE_INTEGER) && bigVal <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(bigVal);
  }
  return bigVal;
}

function decodeCborItem(buf, offset) {
  if (offset >= buf.length) {
    throw new Error('Unexpected end of CBOR input');
  }
  const initial = buf[offset];
  const major = initial >>> 5;
  const info = initial & 0x1f;
  const cursor = offset + 1;

  if (major === 0) {
    const { value, nextOffset } = readCborArg(buf, cursor, info);
    return { value: toJsInteger(value), nextOffset };
  }
  if (major === 1) {
    const { value, nextOffset } = readCborArg(buf, cursor, info);
    return { value: toJsInteger(-1n - value), nextOffset };
  }
  if (major === 2) {
    const { value: lenBig, nextOffset } = readCborArg(buf, cursor, info);
    const len = Number(lenBig);
    if (nextOffset + len > buf.length) throw new Error('Truncated CBOR byte string');
    const slice = Buffer.from(buf.subarray(nextOffset, nextOffset + len));
    return { value: slice, nextOffset: nextOffset + len };
  }
  if (major === 3) {
    const { value: lenBig, nextOffset } = readCborArg(buf, cursor, info);
    const len = Number(lenBig);
    if (nextOffset + len > buf.length) throw new Error('Truncated CBOR text string');
    const raw = buf.subarray(nextOffset, nextOffset + len);
    const str = raw.toString('utf8');
    // Validate strict UTF-8 round-trip
    if (Buffer.compare(Buffer.from(str, 'utf8'), raw) !== 0) {
      throw new Error('Invalid UTF-8 in CBOR text string');
    }
    return { value: str, nextOffset: nextOffset + len };
  }
  if (major === 4) {
    const { value: countBig, nextOffset: start } = readCborArg(buf, cursor, info);
    const count = Number(countBig);
    const arr = [];
    let pos = start;
    for (let i = 0; i < count; i += 1) {
      const item = decodeCborItem(buf, pos);
      arr.push(item.value);
      pos = item.nextOffset;
    }
    return { value: arr, nextOffset: pos };
  }
  if (major === 5) {
    const { value: countBig, nextOffset: start } = readCborArg(buf, cursor, info);
    const count = Number(countBig);
    const obj = {};
    let pos = start;
    let prevKeyBytes = null;
    for (let i = 0; i < count; i += 1) {
      const keyStart = pos;
      const keyDecoded = decodeCborItem(buf, pos);
      const keyBytes = buf.subarray(keyStart, keyDecoded.nextOffset);
      if (prevKeyBytes !== null) {
        const cmp = Buffer.compare(prevKeyBytes, keyBytes);
        if (cmp === 0) throw new Error('Non-canonical CBOR: DuplicateMapKey');
        if (cmp > 0) throw new Error('Non-canonical CBOR: MapKeysNotSorted');
      }
      prevKeyBytes = keyBytes;
      const valDecoded = decodeCborItem(buf, keyDecoded.nextOffset);
      pos = valDecoded.nextOffset;
      if (typeof keyDecoded.value !== 'string') {
        throw new Error('BuF CBOR maps require string keys');
      }
      obj[keyDecoded.value] = valDecoded.value;
    }
    return { value: obj, nextOffset: pos };
  }
  if (major === 6) {
    throw new Error('Non-canonical CBOR: TagPresent');
  }
  if (major === 7) {
    if (info === 20) return { value: false, nextOffset: cursor };
    if (info === 21) return { value: true, nextOffset: cursor };
    if (info === 22) return { value: null, nextOffset: cursor };
    if (info === 25 || info === 26 || info === 27) {
      throw new Error('Non-canonical CBOR: FloatPresent');
    }
    if (info === 31) {
      throw new Error('Non-canonical CBOR: IndefiniteLength');
    }
    throw new Error(`Unsupported CBOR simple value: ${info}`);
  }
  throw new Error(`Unsupported CBOR major type: ${major}`);
}

export function decodeCanonicalCbor(bytes) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buf.length === 0) {
    throw new Error('Empty CBOR input');
  }
  const { value, nextOffset } = decodeCborItem(buf, 0);
  if (nextOffset !== buf.length) {
    throw new Error('Trailing bytes after canonical CBOR item');
  }
  const reencoded = encodeCanonicalCbor(value);
  if (Buffer.compare(reencoded, buf) !== 0) {
    throw new Error('Input CBOR failed differential canonical re-encode check');
  }
  return value;
}

// ============================================================================
// BuF Binary Packager, Signer & Parser (fayger-buf + fayger-loader compatible)
// ============================================================================

function normalizeKind(kind) {
  if (typeof kind === 'string') {
    if (!SECTION_KIND_UNITS.has(kind)) {
      throw new Error(`Invalid section kind '${kind}'; expected code|data|asset|signature or { custom }`);
    }
    return kind;
  }
  if (kind && typeof kind === 'object' && typeof kind.custom === 'string' && kind.custom.length > 0) {
    return { custom: kind.custom };
  }
  throw new Error('Invalid section kind');
}

function sortUniqueStrings(list) {
  const unique = Array.from(new Set(list ?? []));
  for (const item of unique) {
    if (typeof item !== 'string') throw new Error('Expected string list');
  }
  // Rust BTreeSet<String> orders by UTF-8 byte sequence
  unique.sort((a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
  return unique;
}

function normalizeProfileConstraints(pc = {}) {
  const out = {};
  const caps = sortUniqueStrings(pc.required_capabilities ?? pc.requiredCapabilities ?? []);
  if (caps.length > 0) {
    out.required_capabilities = caps;
  }
  const maxSize = pc.max_size ?? pc.maxSize;
  if (maxSize !== undefined && maxSize !== null) {
    if (!Number.isInteger(maxSize) || maxSize < 0) {
      throw new Error('profile_constraints.max_size must be a non-negative integer');
    }
    out.max_size = maxSize;
  }
  const feats = sortUniqueStrings(pc.required_features ?? pc.requiredFeatures ?? []);
  if (feats.length > 0) {
    out.required_features = feats;
  }
  return out;
}

function normalizeQuotas(quotas) {
  if (!quotas) return undefined;
  const out = {};
  const cpu = quotas.cpu_ms_per_sec ?? quotas.cpuMsPerSec;
  const mem = quotas.memory_bytes ?? quotas.memoryBytes;
  const io = quotas.io_bytes_per_sec ?? quotas.ioBytesPerSec;
  if (cpu !== undefined && cpu !== null) {
    if (!Number.isInteger(cpu) || cpu < 0 || cpu > 0xffffffff) {
      throw new Error('quotas.cpu_ms_per_sec must be a valid u32 integer');
    }
    out.cpu_ms_per_sec = cpu;
  }
  if (mem !== undefined && mem !== null) {
    if (!Number.isInteger(mem) || mem < 0) {
      throw new Error('quotas.memory_bytes must be a non-negative integer');
    }
    out.memory_bytes = mem;
  }
  if (io !== undefined && io !== null) {
    if (!Number.isInteger(io) || io < 0) {
      throw new Error('quotas.io_bytes_per_sec must be a non-negative integer');
    }
    out.io_bytes_per_sec = io;
  }
  return out;
}

function normalizeRuntime(runtime) {
  if (!runtime) return undefined;
  const strategy = runtime.selection_strategy ?? runtime.selectionStrategy;
  if (!SELECTION_STRATEGIES.has(strategy)) {
    throw new Error(`Invalid runtime.selection_strategy: ${String(strategy)}`);
  }
  const out = { selection_strategy: strategy };
  const preferred = runtime.preferred_impl ?? runtime.preferredImpl;
  if (typeof preferred === 'string' && preferred.length > 0) {
    out.preferred_impl = preferred;
  }
  return out;
}

function writeHeaderBuffer({
  formatVersion,
  manifestOffset,
  manifestLength,
  sectionIndexOffset,
  sectionIndexLength,
}) {
  const buf = Buffer.alloc(BUF_HEADER_SIZE);
  BUF_MAGIC.copy(buf, 0);
  buf.writeUInt32LE(formatVersion >>> 0, 4);
  buf.writeBigUInt64LE(BigInt(manifestOffset), 8);
  buf.writeBigUInt64LE(BigInt(manifestLength), 16);
  buf.writeBigUInt64LE(BigInt(sectionIndexOffset), 24);
  buf.writeBigUInt64LE(BigInt(sectionIndexLength), 32);
  return buf;
}

function computeNormalizedSigningScope(formatVersion, manifestWithoutSig, sectionIndexBytes) {
  const manifestNoSigBytes = encodeCanonicalCbor(manifestWithoutSig);
  const normHeader = writeHeaderBuffer({
    formatVersion,
    manifestOffset: BUF_HEADER_SIZE,
    manifestLength: manifestNoSigBytes.length,
    sectionIndexOffset: BUF_HEADER_SIZE + manifestNoSigBytes.length,
    sectionIndexLength: sectionIndexBytes.length,
  });
  return Buffer.concat([normHeader, manifestNoSigBytes, sectionIndexBytes]);
}

export function packBufBinary(spec = {}) {
  const formatVersion = spec.formatVersion ?? BUF_FORMAT_VERSION_M0;
  const schemaVersion = spec.schemaVersion ?? spec.schema_version ?? '1.0.0';
  const runtimeInterfaceMin = spec.runtimeInterfaceMin ?? spec.runtime_interface_min ?? '1.0.0';
  const entry = spec.entry ?? 'main';

  if (!isValidBufSemVer(schemaVersion)) {
    throw new Error(`Invalid BuF schema_version '${schemaVersion}'`);
  }
  if (!isValidBufSemVer(runtimeInterfaceMin)) {
    throw new Error(`Invalid BuF runtime_interface_min '${runtimeInterfaceMin}'`);
  }
  if (typeof entry !== 'string' || entry.length === 0) {
    throw new Error('BuF manifest entry must be a non-empty string');
  }

  const rawSections = spec.sections ?? [];
  const seenIds = new Set();
  const payloadBuffers = [];
  const manifestSections = [];
  const sectionIndexEntries = [];
  let cumulativeOffset = 0;

  for (const item of rawSections) {
    const id = item.id;
    if (typeof id !== 'string' || id.length === 0) {
      throw new Error('Every BuF section must have a non-empty string id');
    }
    if (seenIds.has(id)) {
      throw new Error(`Duplicate BuF section id '${id}'`);
    }
    seenIds.add(id);

    const kind = normalizeKind(item.kind ?? 'data');
    const visibility = item.visibility ?? 'required';
    if (!SECTION_VISIBILITIES.has(visibility)) {
      throw new Error(`Invalid section visibility '${visibility}'`);
    }
    const profileConstraints = normalizeProfileConstraints(
      item.profile_constraints ?? item.profileConstraints,
    );

    const payloadBuf =
      typeof item.payload === 'string'
        ? Buffer.from(item.payload, 'utf8')
        : Buffer.from(item.payload ?? []);
    // Note: in fayger-buf Rust serde, Digest.value is Vec<u8> (without serde_bytes),
    // which canonical_encode writes as a CBOR array of 32 u8 integers (0..255).
    const digest = {
      algorithm: 'sha256',
      value: Array.from(sha256Bytes(payloadBuf)),
    };

    manifestSections.push({
      id,
      kind,
      digest,
      length: payloadBuf.length,
      visibility,
      profile_constraints: profileConstraints,
    });

    sectionIndexEntries.push({
      section_id: id,
      kind,
      offset: cumulativeOffset,
      length: payloadBuf.length,
      digest,
      visibility,
      profile_constraints: profileConstraints,
    });

    payloadBuffers.push(payloadBuf);
    cumulativeOffset += payloadBuf.length;
  }

  const manifestObj = {
    schema_version: schemaVersion,
    runtime_interface_min: runtimeInterfaceMin,
    entry,
    sections: manifestSections,
  };

  if (typeof spec.deprecationNotice === 'string') {
    manifestObj.deprecation_notice = spec.deprecationNotice;
  } else if (typeof spec.deprecation_notice === 'string') {
    manifestObj.deprecation_notice = spec.deprecation_notice;
  }

  const runtime = normalizeRuntime(spec.runtime);
  if (runtime) {
    manifestObj.runtime = runtime;
  }

  const capabilities = sortUniqueStrings(spec.capabilities ?? []);
  if (capabilities.length > 0) {
    manifestObj.capabilities = capabilities;
  }

  const quotas = normalizeQuotas(spec.quotas);
  if (quotas) {
    manifestObj.quotas = quotas;
  }

  if (spec.extensions && typeof spec.extensions === 'object') {
    for (const [k, v] of Object.entries(spec.extensions)) {
      if (KNOWN_MANIFEST_FIELDS.has(k)) {
        throw new Error(`BuF extensions cannot override reserved manifest key '${k}'`);
      }
      if (v !== undefined) {
        manifestObj[k] = v;
      }
    }
  }

  const sectionIndexBytes = encodeCanonicalCbor(sectionIndexEntries);

  if (spec.signer) {
    const rawSeed =
      typeof spec.signer.seed32 === 'string'
        ? Buffer.from(spec.signer.seed32, 'hex')
        : Buffer.from(spec.signer.seed32);
    if (rawSeed.length !== 32) {
      throw new RangeError('BuF signer.seed32 must be 32 bytes');
    }
    const keyRef = spec.signer.publicKeyRef ?? spec.signer.keyRef;
    if (typeof keyRef !== 'string' || keyRef.length === 0) {
      throw new Error('BuF signer.publicKeyRef must be a non-empty string');
    }
    const scope = computeNormalizedSigningScope(formatVersion, manifestObj, sectionIndexBytes);
    const sigBuf = signEd25519(rawSeed, scope);
    manifestObj.signature = {
      algorithm: BUF_SIG_ALG_ED25519,
      public_key_ref: keyRef,
      signed_digest: Array.from(sigBuf),
    };
  } else if (spec.signature) {
    manifestObj.signature = {
      algorithm: spec.signature.algorithm ?? BUF_SIG_ALG_ED25519,
      public_key_ref: spec.signature.public_key_ref,
      signed_digest: Array.from(spec.signature.signed_digest),
    };
  }

  const manifestBytes = encodeCanonicalCbor(manifestObj);
  const manifestOffset = BUF_HEADER_SIZE;
  const manifestLength = manifestBytes.length;
  const sectionIndexOffset = manifestOffset + manifestLength;
  const sectionIndexLength = sectionIndexBytes.length;
  const sectionsOffset = sectionIndexOffset + sectionIndexLength;
  const totalLength = sectionsOffset + cumulativeOffset + BUF_TRAILER_SIZE;

  const headerBytes = writeHeaderBuffer({
    formatVersion,
    manifestOffset,
    manifestLength,
    sectionIndexOffset,
    sectionIndexLength,
  });

  const skeletonBytes = Buffer.concat([headerBytes, manifestBytes, sectionIndexBytes]);
  const manifestDigest = sha256Bytes(skeletonBytes);

  const trailerPrefix = Buffer.alloc(8 + BUF_MANIFEST_DIGEST_SIZE);
  trailerPrefix.writeBigUInt64LE(BigInt(totalLength), 0);
  manifestDigest.copy(trailerPrefix, 8);

  const bodyWithoutCrc = Buffer.concat([skeletonBytes, ...payloadBuffers, trailerPrefix]);
  const crc = crc32Ieee(bodyWithoutCrc);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32LE(crc, 0);

  return Buffer.concat([bodyWithoutCrc, crcBuf]);
}

function bytesFromIntArray(arr, label) {
  if (!Array.isArray(arr)) {
    throw new Error(`${label} must be a CBOR byte-value array`);
  }
  for (const b of arr) {
    if (!Number.isInteger(b) || b < 0 || b > 255) {
      throw new Error(`${label} contains non-u8 element`);
    }
  }
  return Buffer.from(arr);
}

export function parseBufBinary(inputBytes, options = {}) {
  const bytes = Buffer.isBuffer(inputBytes) ? inputBytes : Buffer.from(inputBytes);
  if (bytes.length < BUF_HEADER_SIZE + BUF_TRAILER_SIZE) {
    throw new Error(`LDR_PARSE_FAIL [Truncated]: stream length ${bytes.length} < 84`);
  }
  if (Buffer.compare(bytes.subarray(0, 4), BUF_MAGIC) !== 0) {
    throw new Error('LDR_PARSE_FAIL [MagicMismatch]: magic does not match BUF\\0');
  }

  const formatVersion = bytes.readUInt32LE(4);
  const manifestOffset = Number(bytes.readBigUInt64LE(8));
  const manifestLength = Number(bytes.readBigUInt64LE(16));
  const sectionIndexOffset = Number(bytes.readBigUInt64LE(24));
  const sectionIndexLength = Number(bytes.readBigUInt64LE(32));

  if (manifestOffset !== BUF_HEADER_SIZE) {
    throw new Error(
      `LDR_PARSE_FAIL [OffsetOutOfBounds]: manifest_offset ${manifestOffset} !== ${BUF_HEADER_SIZE}`,
    );
  }
  if (sectionIndexOffset !== manifestOffset + manifestLength) {
    throw new Error('LDR_PARSE_FAIL [OffsetOutOfBounds]: non-contiguous section_index_offset');
  }

  const sectionsOffset = sectionIndexOffset + sectionIndexLength;
  const trailerOffset = bytes.length - BUF_TRAILER_SIZE;
  if (sectionsOffset > trailerOffset) {
    throw new Error('LDR_PARSE_FAIL [OffsetOutOfBounds]: sections region overlaps trailer');
  }

  let rawManifest;
  try {
    rawManifest = decodeCanonicalCbor(bytes.subarray(manifestOffset, manifestOffset + manifestLength));
  } catch (err) {
    throw new Error(`LDR_PARSE_FAIL [ManifestInvalid]: ${err.message}`);
  }
  if (!rawManifest || typeof rawManifest !== 'object' || Array.isArray(rawManifest)) {
    throw new Error('LDR_PARSE_FAIL [ManifestInvalid]: manifest is not a CBOR map');
  }

  for (const reqKey of ['schema_version', 'runtime_interface_min', 'entry', 'sections']) {
    if (!(reqKey in rawManifest)) {
      throw new Error(`LDR_PARSE_FAIL [ManifestMissingField]: missing '${reqKey}'`);
    }
  }
  if (!isValidBufSemVer(rawManifest.schema_version)) {
    throw new Error('LDR_PARSE_FAIL [ManifestInvalid]: invalid schema_version SemVer');
  }
  if (!isValidBufSemVer(rawManifest.runtime_interface_min)) {
    throw new Error('LDR_PARSE_FAIL [ManifestInvalid]: invalid runtime_interface_min SemVer');
  }
  if (typeof rawManifest.entry !== 'string' || rawManifest.entry.length === 0) {
    throw new Error('LDR_MISSING_REQUIRED_FIELD: empty entry');
  }
  if (!Array.isArray(rawManifest.sections)) {
    throw new Error('LDR_PARSE_FAIL [ManifestInvalid]: sections must be an array');
  }

  let sectionIndex;
  try {
    sectionIndex = decodeCanonicalCbor(
      bytes.subarray(sectionIndexOffset, sectionIndexOffset + sectionIndexLength),
    );
  } catch (err) {
    throw new Error(`LDR_PARSE_FAIL [SectionIndexInvalid]: ${err.message}`);
  }
  if (!Array.isArray(sectionIndex)) {
    throw new Error('LDR_PARSE_FAIL [SectionIndexInvalid]: section index must be an array');
  }

  const trailerSlice = bytes.subarray(trailerOffset);
  const totalLength = Number(trailerSlice.readBigUInt64LE(0));
  const manifestDigest = Buffer.from(trailerSlice.subarray(8, 40));
  const crc32 = trailerSlice.readUInt32LE(40);

  if (totalLength !== bytes.length) {
    throw new Error(
      `LDR_PARSE_FAIL [TrailerLengthMismatch]: trailer=${totalLength} actual=${bytes.length}`,
    );
  }

  if (sectionIndex.length !== rawManifest.sections.length) {
    throw new Error('LDR_PARSE_FAIL [SectionMismatch]: index count !== manifest.sections count');
  }

  const sectionsRegion = bytes.subarray(sectionsOffset, trailerOffset);
  let expectedOffset = 0;
  const sections = [];

  for (let i = 0; i < sectionIndex.length; i += 1) {
    const idxEntry = sectionIndex[i];
    const desc = rawManifest.sections[i];
    if (idxEntry.section_id !== desc.id) {
      throw new Error(`LDR_PARSE_FAIL [SectionMismatch]: id mismatch at ${i}`);
    }
    if (idxEntry.length !== desc.length) {
      throw new Error(`LDR_PARSE_FAIL [SectionMismatch]: length mismatch at ${desc.id}`);
    }
    if (idxEntry.offset !== expectedOffset) {
      throw new Error(`LDR_PARSE_FAIL [SectionOutOfBounds]: non-contiguous offset at ${desc.id}`);
    }
    const end = idxEntry.offset + idxEntry.length;
    if (end > sectionsRegion.length) {
      throw new Error(`LDR_PARSE_FAIL [SectionOutOfBounds]: section '${desc.id}' exceeds region`);
    }
    const payload = Buffer.from(sectionsRegion.subarray(idxEntry.offset, end));
    sections.push({
      id: desc.id,
      kind: desc.kind,
      visibility: desc.visibility,
      digestHex: bytesFromIntArray(desc.digest.value, `section[${desc.id}].digest.value`).toString('hex'),
      payload,
    });
    expectedOffset = end;
  }

  if (expectedOffset !== sectionsRegion.length) {
    throw new Error('LDR_PARSE_FAIL [SectionOutOfBounds]: trailing undeclared bytes in sections region');
  }

  const verifyDigest = options.verifyDigest !== false;
  if (verifyDigest) {
    const actualManifestDigest = sha256Bytes(bytes.subarray(0, sectionsOffset));
    if (Buffer.compare(actualManifestDigest, manifestDigest) !== 0) {
      throw new Error('LDR_DIGEST_MISMATCH [ManifestDigest]: manifest_digest mismatch');
    }

    for (let i = 0; i < sections.length; i += 1) {
      const desc = rawManifest.sections[i];
      if (desc.digest?.algorithm !== 'sha256') {
        throw new Error(
          `LDR_DIGEST_MISMATCH [UnsupportedDigestAlgorithm]: ${String(desc.digest?.algorithm)}`,
        );
      }
      const declaredBytes = bytesFromIntArray(desc.digest.value, 'digest.value');
      const actualBytes = sha256Bytes(sections[i].payload);
      if (Buffer.compare(declaredBytes, actualBytes) !== 0) {
        throw new Error(`LDR_DIGEST_MISMATCH [SectionDigest]: digest mismatch in '${sections[i].id}'`);
      }
    }

    const actualCrc = crc32Ieee(bytes.subarray(0, bytes.length - 4));
    if (actualCrc !== crc32) {
      throw new Error(`LDR_DIGEST_MISMATCH [Crc32]: expected ${crc32}, actual ${actualCrc}`);
    }
  }

  const extensions = {};
  for (const [k, v] of Object.entries(rawManifest)) {
    if (!KNOWN_MANIFEST_FIELDS.has(k)) {
      extensions[k] = v;
    }
  }

  let signatureStatus = 'absent';
  if (rawManifest.signature) {
    signatureStatus = 'unverified';
    const sigBlock = rawManifest.signature;
    const trustAnchors = options.trustAnchors ?? {};
    const trustedHex =
      options.trustedPublicKeyHex ?? trustAnchors[sigBlock.public_key_ref] ?? null;

    if (options.requireSignatureVerification && !trustedHex) {
      throw new Error(`LDR_SIGNATURE_FAIL [UnknownKey]: ${sigBlock.public_key_ref}`);
    }
    if (trustedHex) {
      if (sigBlock.algorithm !== BUF_SIG_ALG_ED25519) {
        throw new Error(`LDR_SIGNATURE_FAIL [UnsupportedAlgorithm]: ${sigBlock.algorithm}`);
      }
      const manifestWithoutSig = { ...rawManifest };
      delete manifestWithoutSig.signature;
      const sidxBytes = bytes.subarray(sectionIndexOffset, sectionIndexOffset + sectionIndexLength);
      const scope = computeNormalizedSigningScope(formatVersion, manifestWithoutSig, sidxBytes);
      const sigBytes = bytesFromIntArray(sigBlock.signed_digest, 'signature.signed_digest');
      if (!verifyEd25519(trustedHex, scope, sigBytes)) {
        throw new Error('LDR_SIGNATURE_FAIL [InvalidSignature]: Ed25519 signature invalid');
      }
      signatureStatus = 'valid';
    }
  } else if (options.requireSignatureVerification) {
    throw new Error('LDR_SIGNATURE_FAIL [MissingSignature]: signature block missing');
  }

  return {
    header: {
      magic: 'BUF\\0',
      formatVersion,
      manifestOffset,
      manifestLength,
      sectionIndexOffset,
      sectionIndexLength,
      sectionsOffset,
    },
    manifest: {
      schema_version: rawManifest.schema_version,
      runtime_interface_min: rawManifest.runtime_interface_min,
      deprecation_notice: rawManifest.deprecation_notice ?? null,
      entry: rawManifest.entry,
      runtime: rawManifest.runtime ?? null,
      capabilities: rawManifest.capabilities ?? [],
      quotas: rawManifest.quotas ?? null,
      sections: rawManifest.sections,
      signature: rawManifest.signature ?? null,
      extensions,
    },
    sectionIndex,
    sections,
    trailer: {
      totalLength,
      manifestDigestHex: manifestDigest.toString('hex'),
      crc32,
    },
    verified: {
      digestValid: verifyDigest,
      crc32Valid: verifyDigest,
      signatureStatus,
    },
  };
}

export function formatBufInspection(parsed) {
  const m = parsed.manifest;
  const lines = [
    'BuF Manifest',
    `  schema_version:        ${m.schema_version}`,
    `  runtime_interface_min: ${m.runtime_interface_min}`,
    `  entry:                 ${m.entry}`,
    `  sections:              ${m.sections.length}`,
  ];
  for (const s of m.sections) {
    const kindStr = typeof s.kind === 'string' ? s.kind : `custom:${s.kind.custom}`;
    lines.push(`    - ${s.id} [${kindStr}] len=${s.length} ${s.visibility}`);
  }
  lines.push(
    `  capabilities:          ${m.capabilities.length > 0 ? m.capabilities.join(', ') : '(none)'}`,
  );
  if (m.quotas) {
    lines.push(
      `  quotas:                cpu_ms_per_sec=${m.quotas.cpu_ms_per_sec ?? 'None'} memory_bytes=${m.quotas.memory_bytes ?? 'None'} io_bytes_per_sec=${m.quotas.io_bytes_per_sec ?? 'None'}`,
    );
  } else {
    lines.push('  quotas:                (none)');
  }
  lines.push(`  signature:             ${m.signature ? 'present' : 'absent'}`);
  lines.push(`  manifest_digest_sha256:${parsed.trailer.manifestDigestHex}`);
  lines.push(`  crc32:                 0x${parsed.trailer.crc32.toString(16).padStart(8, '0')}`);
  return lines.join('\n');
}
