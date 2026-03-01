// BareMetalBinary — BSO1 binary wire serializer for BareMetalWeb
// Mirrors MetadataWireSerializer.cs: metadata-driven, zero-copy DataView reads,
// HMAC-SHA256 signing via Web Crypto API.
const BareMetalBinary = (() => {
  'use strict';

  const MAGIC = 0x314F5342; // "BSO1" LE
  const VERSION = 3;
  const SIG_SIZE = 32;
  const HDR_FIELDS = 13; // magic(4) + version(4) + schema(4) + arch(1)
  const HDR_SIZE = HDR_FIELDS + SIG_SIZE; // 45
  const MAX_STR = 4 * 1024 * 1024;
  const MAX_DEPTH = 64;
  const utf8 = new TextEncoder();
  const utf8d = new TextDecoder('utf-8');

  let _cryptoKey = null; // CryptoKey for HMAC-SHA256

  // ────────── Key management ──────────

  async function setSigningKey(base64Key) {
    const raw = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
    _cryptoKey = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  }

  async function setSigningKeyBytes(keyBytes) {
    _cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  }

  // ────────── SpanReader ──────────

  class SpanReader {
    constructor(buffer) {
      this.dv = new DataView(buffer instanceof ArrayBuffer ? buffer : buffer.buffer, buffer.byteOffset || 0, buffer.byteLength);
      this.buf = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer, buffer.byteOffset || 0, buffer.byteLength);
      this.off = 0;
    }
    ensure(n) { if (this.off + n > this.dv.byteLength) throw new Error('EOF'); }
    readByte() { this.ensure(1); return this.dv.getUint8(this.off++); }
    readSByte() { this.ensure(1); return this.dv.getInt8(this.off++); }
    readBool() { return this.readByte() !== 0; }
    readInt16() { this.ensure(2); const v = this.dv.getInt16(this.off, true); this.off += 2; return v; }
    readUInt16() { this.ensure(2); const v = this.dv.getUint16(this.off, true); this.off += 2; return v; }
    readInt32() { this.ensure(4); const v = this.dv.getInt32(this.off, true); this.off += 4; return v; }
    readUInt32() { this.ensure(4); const v = this.dv.getUint32(this.off, true); this.off += 4; return v; }
    readInt64() {
      this.ensure(8);
      const lo = this.dv.getUint32(this.off, true);
      const hi = this.dv.getInt32(this.off + 4, true);
      this.off += 8;
      return BigInt(hi) * 0x100000000n + BigInt(lo >>> 0);
    }
    readUInt64() {
      this.ensure(8);
      const lo = this.dv.getUint32(this.off, true);
      const hi = this.dv.getUint32(this.off + 4, true);
      this.off += 8;
      return BigInt(hi) * 0x100000000n + BigInt(lo >>> 0);
    }
    readFloat32() { this.ensure(4); const v = this.dv.getFloat32(this.off, true); this.off += 4; return v; }
    readFloat64() { this.ensure(8); const v = this.dv.getFloat64(this.off, true); this.off += 8; return v; }
    readDecimal() {
      const lo = this.readInt32(); const mid = this.readInt32();
      const hi = this.readInt32(); const flags = this.readInt32();
      const neg = (flags & 0x80000000) !== 0;
      const scale = (flags >>> 16) & 0xFF;
      // Reconstruct as JS number (lossy for very large decimals)
      let val = (Math.abs(hi) * 4294967296 + (mid >>> 0)) * 4294967296 + (lo >>> 0);
      val /= Math.pow(10, scale);
      return neg ? -val : val;
    }
    readChar() { return String.fromCharCode(this.readUInt16()); }
    readBytes(n) { this.ensure(n); const s = this.buf.slice(this.off, this.off + n); this.off += n; return s; }
    readGuid() {
      const b = this.readBytes(16);
      const h = Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
      return h.slice(0,8)+'-'+h.slice(8,12)+'-'+h.slice(12,16)+'-'+h.slice(16,20)+'-'+h.slice(20);
    }
    readIdentifier() {
      // 16 bytes: hi LE (8) + lo LE (8) — base-37 encoded
      const hiLo = this.readUInt64();
      const loLo = this.readUInt64();
      return decodeIdentifier(hiLo, loLo);
    }
    skip(n) { this.off += n; }
  }

  // ────────── SpanWriter ──────────

  class SpanWriter {
    constructor(initialSize) {
      this.capacity = initialSize || 256;
      this.buf = new ArrayBuffer(this.capacity);
      this.u8 = new Uint8Array(this.buf);
      this.dv = new DataView(this.buf);
      this.off = 0;
    }
    ensure(n) {
      if (this.off + n <= this.capacity) return;
      while (this.off + n > this.capacity) this.capacity *= 2;
      const nb = new ArrayBuffer(this.capacity);
      new Uint8Array(nb).set(this.u8.subarray(0, this.off));
      this.buf = nb; this.u8 = new Uint8Array(nb); this.dv = new DataView(nb);
    }
    writeByte(v) { this.ensure(1); this.dv.setUint8(this.off++, v); }
    writeSByte(v) { this.ensure(1); this.dv.setInt8(this.off++, v); }
    writeBool(v) { this.writeByte(v ? 1 : 0); }
    writeInt16(v) { this.ensure(2); this.dv.setInt16(this.off, v, true); this.off += 2; }
    writeUInt16(v) { this.ensure(2); this.dv.setUint16(this.off, v, true); this.off += 2; }
    writeInt32(v) { this.ensure(4); this.dv.setInt32(this.off, v, true); this.off += 4; }
    writeUInt32(v) { this.ensure(4); this.dv.setUint32(this.off, v, true); this.off += 4; }
    writeInt64(v) {
      this.ensure(8);
      const big = BigInt(v);
      this.dv.setUint32(this.off, Number(big & 0xFFFFFFFFn), true);
      this.dv.setInt32(this.off + 4, Number(big >> 32n), true);
      this.off += 8;
    }
    writeUInt64(v) {
      this.ensure(8);
      const big = BigInt(v);
      this.dv.setUint32(this.off, Number(big & 0xFFFFFFFFn), true);
      this.dv.setUint32(this.off + 4, Number((big >> 32n) & 0xFFFFFFFFn), true);
      this.off += 8;
    }
    writeFloat32(v) { this.ensure(4); this.dv.setFloat32(this.off, v, true); this.off += 4; }
    writeFloat64(v) { this.ensure(8); this.dv.setFloat64(this.off, v, true); this.off += 8; }
    writeDecimal(v) {
      // Approximate: encode as 4xInt32 matching .NET decimal layout
      const neg = v < 0; const abs = Math.abs(v);
      const str = abs.toFixed(10); const dot = str.indexOf('.');
      const scale = dot >= 0 ? str.length - dot - 1 : 0;
      let int = BigInt(str.replace('.', ''));
      while (int > 0n && int % 10n === 0n && scale > 0) int /= 10n; // normalize
      const lo = Number(int & 0xFFFFFFFFn);
      const mid = Number((int >> 32n) & 0xFFFFFFFFn);
      const hi = Number((int >> 64n) & 0xFFFFFFFFn);
      const flags = (scale << 16) | (neg ? 0x80000000 : 0);
      this.writeInt32(lo); this.writeInt32(mid); this.writeInt32(hi); this.writeInt32(flags);
    }
    writeChar(v) { this.writeUInt16(typeof v === 'string' ? v.charCodeAt(0) : v); }
    writeBytes(bytes) { this.ensure(bytes.length); this.u8.set(bytes, this.off); this.off += bytes.length; }
    writeGuid(str) {
      const hex = str.replace(/-/g, '');
      const b = new Uint8Array(16);
      for (let i = 0; i < 16; i++) b[i] = parseInt(hex.substr(i*2, 2), 16);
      this.writeBytes(b);
    }
    writeString(s) {
      if (s === null || s === undefined) { this.writeInt32(-1); return; }
      const bytes = utf8.encode(s);
      this.writeInt32(bytes.length);
      if (bytes.length > 0) this.writeBytes(bytes);
    }
    writeIdentifier(str) {
      const [hi, lo] = encodeIdentifier(str);
      this.writeUInt64(hi); this.writeUInt64(lo);
    }
    toUint8Array() { return new Uint8Array(this.buf, 0, this.off); }
  }

  // ────────── IdentifierValue codec ──────────

  const ID_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-';
  const ID_MAX_LEN = 25;

  function decodeIdentifier(hi, lo) {
    if (hi === 0n && lo === 0n) return '';
    const length = Number((hi >> 59n) & 0x1Fn);
    if (length === 0 || length > ID_MAX_LEN) return '';
    hi = hi & 0x07FFFFFFFFFFFFFFn;
    const chars = [];
    for (let i = length - 1; i >= 0; i--) {
      // divide 128-bit by 37
      const qHi = hi / 37n; const rHi = hi % 37n;
      const combined1 = (rHi << 32n) | (lo >> 32n);
      const qMid = combined1 / 37n; const rMid = combined1 % 37n;
      const combined2 = (rMid << 32n) | (lo & 0xFFFFFFFFn);
      const qLo = combined2 / 37n; const remainder = combined2 % 37n;
      chars[i] = ID_ALPHABET[Number(remainder)];
      hi = qHi; lo = (qMid << 32n) | qLo;
    }
    return chars.join('');
  }

  function encodeIdentifier(str) {
    if (!str || str.length === 0) return [0n, 0n];
    const norm = str.toUpperCase().replace(/[^A-Z0-9-]/g, '');
    if (norm.length > ID_MAX_LEN) throw new Error('Identifier too long');
    let hi = 0n, lo = 0n;
    for (let i = 0; i < norm.length; i++) {
      const idx = ID_ALPHABET.indexOf(norm[i]);
      if (idx < 0) throw new Error(`Invalid char '${norm[i]}'`);
      // multiply 128-bit by 37 and add
      const loCarry = (lo * 37n) >> 64n;
      lo = (lo * 37n) & 0xFFFFFFFFFFFFFFFFn;
      hi = hi * 37n + loCarry;
      lo = lo + BigInt(idx);
      if (lo > 0xFFFFFFFFFFFFFFFFn) { hi++; lo = lo & 0xFFFFFFFFFFFFFFFFn; }
    }
    hi |= BigInt(norm.length) << 59n;
    return [hi, lo];
  }

  // ────────── HMAC-SHA256 signing ──────────

  async function computeSignature(payload) {
    // Sign header fields + payload after signature (skip the 32-byte signature slot)
    const parts = new Uint8Array(payload.length - SIG_SIZE);
    parts.set(payload.subarray(0, HDR_FIELDS));
    parts.set(payload.subarray(HDR_SIZE), HDR_FIELDS);
    const sig = await crypto.subtle.sign('HMAC', _cryptoKey, parts);
    return new Uint8Array(sig);
  }

  async function signPayload(payload) {
    const sig = await computeSignature(payload);
    payload.set(sig, HDR_FIELDS);
  }

  async function verifySignature(payload) {
    const expected = await computeSignature(payload);
    const actual = payload.subarray(HDR_FIELDS, HDR_SIZE);
    if (expected.length !== actual.length) return false;
    let ok = true;
    for (let i = 0; i < expected.length; i++) ok = ok && (expected[i] === actual[i]);
    return ok;
  }

  // ────────── Schema cache ──────────

  const _schemas = {}; // slug → { version, members: [{name, ordinal, wireType, isNullable, enumUnderlying}] }

  async function fetchSchema(slug, apiRoot) {
    if (_schemas[slug]) return _schemas[slug];
    const url = (apiRoot || '/api/') + '_binary/' + slug + '/_schema';
    const r = await fetch(url);
    if (!r.ok) throw new Error(`Schema fetch failed: ${r.status}`);
    const schema = await r.json();
    _schemas[slug] = schema;
    return schema;
  }

  function getCachedSchema(slug) { return _schemas[slug] || null; }

  // ────────── Deserialize ──────────

  function readFieldValue(reader, member, depth) {
    if (depth > MAX_DEPTH) throw new Error('Max depth exceeded');

    if (member.isNullable) {
      if (reader.readByte() === 0) return null;
    }

    switch (member.wireType) {
      case 'Bool': return reader.readBool();
      case 'Byte': return reader.readByte();
      case 'SByte': return reader.readSByte();
      case 'Int16': return reader.readInt16();
      case 'UInt16': return reader.readUInt16();
      case 'Int32': return reader.readInt32();
      case 'UInt32': return reader.readUInt32();
      case 'Int64': return reader.readInt64();
      case 'UInt64': return reader.readUInt64();
      case 'Float32': return reader.readFloat32();
      case 'Float64': return reader.readFloat64();
      case 'Decimal': return reader.readDecimal();
      case 'Char': return reader.readChar();
      case 'String': return readString(reader);
      case 'Guid': return reader.readGuid();
      case 'DateTime': return readDateTime(reader);
      case 'DateOnly': return readDateOnly(reader);
      case 'TimeOnly': return readTimeOnly(reader);
      case 'DateTimeOffset': return readDateTimeOffset(reader);
      case 'TimeSpan': return reader.readInt64(); // ticks as BigInt
      case 'Identifier': return reader.readIdentifier();
      case 'Enum': return readEnum(reader, member);
      default: return readString(reader); // fallback
    }
  }

  function readString(reader) {
    const len = reader.readInt32();
    if (len < 0) return null;
    if (len === 0) return '';
    if (len > MAX_STR) throw new Error('String too long');
    const bytes = reader.readBytes(len);
    return utf8d.decode(bytes);
  }

  function readDateTime(reader) {
    const ticks = reader.readInt64();
    const kind = reader.readByte();
    // .NET ticks → JS Date (ticks from 0001-01-01, JS from 1970-01-01)
    const epochTicks = 621355968000000000n;
    const ms = Number((ticks - epochTicks) / 10000n);
    return new Date(ms);
  }

  function readDateOnly(reader) {
    const dayNumber = reader.readInt32();
    // .NET DateOnly.DayNumber: days from 0001-01-01
    const ms = (dayNumber - 719162) * 86400000; // 719162 = days from 0001-01-01 to 1970-01-01
    return new Date(ms).toISOString().slice(0, 10);
  }

  function readTimeOnly(reader) {
    const ticks = reader.readInt64();
    const totalSec = Number(ticks / 10000000n);
    const h = Math.floor(totalSec / 3600);
    const m = Math.floor((totalSec % 3600) / 60);
    const s = totalSec % 60;
    return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
  }

  function readDateTimeOffset(reader) {
    const ticks = reader.readInt64();
    const offsetMin = reader.readInt16();
    const epochTicks = 621355968000000000n;
    const ms = Number((ticks - epochTicks) / 10000n);
    return new Date(ms - offsetMin * 60000);
  }

  function readEnum(reader, member) {
    const underlying = member.enumUnderlying || 'Int32';
    switch (underlying) {
      case 'Byte': return reader.readByte();
      case 'SByte': return reader.readSByte();
      case 'Int16': return reader.readInt16();
      case 'UInt16': return reader.readUInt16();
      case 'UInt32': return reader.readUInt32();
      case 'Int64': return reader.readInt64();
      case 'UInt64': return reader.readUInt64();
      default: return reader.readInt32();
    }
  }

  async function deserialize(buffer, schema) {
    const u8 = new Uint8Array(buffer);
    if (!await verifySignature(u8)) throw new Error('Signature mismatch');

    const reader = new SpanReader(u8);
    reader.skip(HDR_SIZE); // skip header

    // Object null indicator
    if (reader.readByte() === 0) return null;

    const obj = {};
    for (const m of schema.members) {
      obj[m.name] = readFieldValue(reader, m, 0);
    }
    return obj;
  }

  async function deserializeList(buffer, schema) {
    const u8 = new Uint8Array(buffer);
    if (!await verifySignature(u8)) throw new Error('Signature mismatch');

    const reader = new SpanReader(u8);
    reader.skip(HDR_SIZE); // skip header

    const count = reader.readInt32();
    const items = [];
    for (let i = 0; i < count; i++) {
      const itemLen = reader.readInt32();
      // Object null indicator
      if (reader.readByte() === 0) { items.push(null); continue; }
      const obj = {};
      for (const m of schema.members) {
        obj[m.name] = readFieldValue(reader, m, 0);
      }
      items.push(obj);
    }
    return items;
  }

  // ────────── Serialize ──────────

  function writeFieldValue(writer, member, value, depth) {
    if (depth > MAX_DEPTH) throw new Error('Max depth exceeded');

    if (member.isNullable) {
      if (value === null || value === undefined) { writer.writeByte(0); return; }
      writer.writeByte(1);
    }

    switch (member.wireType) {
      case 'Bool': writer.writeBool(!!value); break;
      case 'Byte': writer.writeByte(value | 0); break;
      case 'SByte': writer.writeSByte(value | 0); break;
      case 'Int16': writer.writeInt16(value | 0); break;
      case 'UInt16': writer.writeUInt16(value | 0); break;
      case 'Int32': writer.writeInt32(value | 0); break;
      case 'UInt32': writer.writeUInt32(value >>> 0); break;
      case 'Int64': writer.writeInt64(BigInt(value || 0)); break;
      case 'UInt64': writer.writeUInt64(BigInt(value || 0)); break;
      case 'Float32': writer.writeFloat32(value || 0); break;
      case 'Float64': writer.writeFloat64(value || 0); break;
      case 'Decimal': writer.writeDecimal(value || 0); break;
      case 'Char': writer.writeChar(value || '\0'); break;
      case 'String': writer.writeString(value ?? null); break;
      case 'Guid': writer.writeGuid(value || '00000000-0000-0000-0000-000000000000'); break;
      case 'DateTime': writeDateTime(writer, value); break;
      case 'DateOnly': writeDateOnly(writer, value); break;
      case 'TimeOnly': writeTimeOnly(writer, value); break;
      case 'DateTimeOffset': writeDateTimeOffset(writer, value); break;
      case 'TimeSpan': writer.writeInt64(BigInt(value || 0)); break;
      case 'Identifier': writer.writeIdentifier(value || ''); break;
      case 'Enum': writeEnum(writer, member, value); break;
      default: writer.writeString(value != null ? String(value) : null); break;
    }
  }

  function writeDateTime(writer, value) {
    const d = value instanceof Date ? value : new Date(value || 0);
    const epochTicks = 621355968000000000n;
    const ticks = epochTicks + BigInt(d.getTime()) * 10000n;
    writer.writeInt64(ticks);
    writer.writeByte(1); // DateTimeKind.Utc
  }

  function writeDateOnly(writer, value) {
    let d;
    if (typeof value === 'string') { const parts = value.split('-'); d = new Date(Date.UTC(+parts[0], +parts[1]-1, +parts[2])); }
    else d = value instanceof Date ? value : new Date(value || 0);
    const dayNumber = Math.floor(d.getTime() / 86400000) + 719162;
    writer.writeInt32(dayNumber);
  }

  function writeTimeOnly(writer, value) {
    let ticks = 0n;
    if (typeof value === 'string') {
      const p = value.split(':').map(Number);
      ticks = BigInt((p[0]||0)*3600 + (p[1]||0)*60 + (p[2]||0)) * 10000000n;
    }
    writer.writeInt64(ticks);
  }

  function writeDateTimeOffset(writer, value) {
    const d = value instanceof Date ? value : new Date(value || 0);
    const epochTicks = 621355968000000000n;
    const ticks = epochTicks + BigInt(d.getTime()) * 10000n;
    writer.writeInt64(ticks);
    writer.writeInt16(0); // UTC offset
  }

  function writeEnum(writer, member, value) {
    const v = value | 0;
    const underlying = member.enumUnderlying || 'Int32';
    switch (underlying) {
      case 'Byte': writer.writeByte(v); break;
      case 'SByte': writer.writeSByte(v); break;
      case 'Int16': writer.writeInt16(v); break;
      case 'UInt16': writer.writeUInt16(v); break;
      case 'UInt32': writer.writeUInt32(v >>> 0); break;
      case 'Int64': writer.writeInt64(BigInt(v)); break;
      case 'UInt64': writer.writeUInt64(BigInt(v)); break;
      default: writer.writeInt32(v); break;
    }
  }

  async function serialize(obj, schema) {
    const writer = new SpanWriter(256);
    // Header
    writer.writeInt32(MAGIC);
    writer.writeInt32(VERSION);
    writer.writeInt32(schema.version || 1);
    writer.writeByte(0); // architecture (irrelevant for wire)
    // Signature placeholder
    for (let i = 0; i < SIG_SIZE; i++) writer.writeByte(0);
    // Object null indicator
    writer.writeByte(1);
    for (const m of schema.members) {
      writeFieldValue(writer, m, obj[m.name], 0);
    }
    const payload = writer.toUint8Array();
    await signPayload(payload);
    return payload.buffer.slice(0, payload.length);
  }

  // ────────── Public API ──────────

  return {
    setSigningKey,
    setSigningKeyBytes,
    fetchSchema,
    getCachedSchema,
    deserialize,
    deserializeList,
    serialize,
    verifySignature,
    // Expose for testing
    SpanReader,
    SpanWriter,
  };
})();
