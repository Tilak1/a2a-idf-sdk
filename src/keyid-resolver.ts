// Dual-shape keyid resolution per A2A-IDF §6 follow-up:
//   • `application/did+json` → W3C DID Document with an Ed25519VerificationKey2020
//     (or 2018) verification method.
//   • else → Envoys §6 compact form `{ address, public_key (PEM SPKI), ... }`.
//
// Both shapes resolve to the same 32-byte Ed25519 raw public key so callers
// can pass the result directly to `rfc9421.verify({ publicKey })`.
//
// Hardware-key path: a document may instead publish an EC P-256 key (a JWK
// {"kty":"EC","crv":"P-256",...} in the DID Document, or a P-256 PEM SPKI in
// the compact form). It resolves to the 65-byte uncompressed point with
// `algorithm: "ecdsa-p256-sha256"`, for `verifyEcdsaP256({ publicKey })`.
// Ed25519 documents resolve exactly as before.

import { createPublicKey } from "node:crypto";

import { p256PointFromJwk, p256PointFromKey } from "./p256.js";

export type KeyAlgorithm = "ed25519" | "ecdsa-p256-sha256";

export interface ResolvedKey {
  /**
   * Raw Ed25519 public key (32 bytes), or for `ecdsa-p256-sha256` the
   * uncompressed P-256 point (65 bytes).
   */
  publicKey: Uint8Array;
  /** Algorithm of `publicKey`; callers must verify with the matching scheme. */
  algorithm: KeyAlgorithm;
  /** Shape we dispatched on. Useful for telemetry / debugging. */
  shape: "did-json" | "compact";
  /** Original document (parsed JSON), for callers needing more context. */
  document: unknown;
}

export interface ResolveOptions {
  /** Inject a fetch implementation (defaults to global `fetch`). */
  fetch?: typeof globalThis.fetch;
  /** Caps the response body size in bytes. Defaults to 64 KiB. */
  maxBytes?: number;
  /** AbortSignal forwarded to the underlying fetch. */
  signal?: AbortSignal;
}

const DEFAULT_MAX_BYTES = 64 * 1024;

export async function resolveKeyid(
  keyidUrl: string,
  options: ResolveOptions = {},
): Promise<ResolvedKey> {
  const u = new URL(keyidUrl); // throws on invalid URL — matches "MUST be absolute" requirement.
  if (u.protocol !== "https:" && u.protocol !== "http:") {
    throw new Error(`keyid URL must be http(s): ${keyidUrl}`);
  }

  const fetchImpl = options.fetch ?? globalThis.fetch;
  const res = await fetchImpl(keyidUrl, { signal: options.signal });
  if (!res.ok) {
    throw new Error(`keyid resolution failed: HTTP ${res.status}`);
  }

  // Bound body size so a hostile endpoint can't DoS the verifier.
  const max = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const bytes = await readBoundedBody(res, max);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const doc: unknown = JSON.parse(text);

  const contentType = (res.headers.get("content-type") ?? "")
    .split(";")[0]!
    .trim()
    .toLowerCase();

  if (contentType === "application/did+json") {
    return { ...extractFromDidDocument(doc), shape: "did-json", document: doc };
  }
  return { ...extractFromCompactForm(doc), shape: "compact", document: doc };
}

async function readBoundedBody(res: Response, max: number): Promise<Uint8Array> {
  // ReadableStream path (preferred, lets us bail early on oversize bodies).
  if (res.body !== null) {
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) {
        await reader.cancel();
        throw new Error(`keyid document exceeds ${max} bytes`);
      }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      out.set(c, offset);
      offset += c.byteLength;
    }
    return out;
  }
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.byteLength > max) {
    throw new Error(`keyid document exceeds ${max} bytes`);
  }
  return buf;
}

// -----------------------------------------------------------------------------
// Compact form (Envoys §6).
// -----------------------------------------------------------------------------

interface CompactKeyDoc {
  address: string;
  public_key: string;
}

interface KeyMaterial {
  publicKey: Uint8Array;
  algorithm: KeyAlgorithm;
}

function extractFromCompactForm(doc: unknown): KeyMaterial {
  if (!isRecord(doc) || typeof doc["public_key"] !== "string") {
    throw new Error("compact keyid document missing string `public_key`");
  }
  const pem = (doc as unknown as CompactKeyDoc).public_key;
  const p256 = tryP256Spki(pem);
  if (p256 !== undefined) {
    return { publicKey: p256, algorithm: "ecdsa-p256-sha256" };
  }
  return { publicKey: decodeEd25519Spki(pem), algorithm: "ed25519" };
}

/** The P-256 point if `pem` is a P-256 SPKI; undefined for any other key. */
function tryP256Spki(pem: string): Uint8Array | undefined {
  try {
    return p256PointFromKey(createPublicKey(pem));
  } catch {
    return undefined;
  }
}

// -----------------------------------------------------------------------------
// DID Document form (W3C DID v1.0, restricted to Ed25519).
// -----------------------------------------------------------------------------

interface DidVerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: { kty?: string; crv?: string; x?: string; y?: string };
}

interface DidDocument {
  id: string;
  verificationMethod?: DidVerificationMethod[];
  assertionMethod?: (string | DidVerificationMethod)[];
}

const ED25519_TYPES = new Set([
  "Ed25519VerificationKey2020",
  "Ed25519VerificationKey2018",
  "JsonWebKey2020",
]);

function extractFromDidDocument(doc: unknown): KeyMaterial {
  if (!isRecord(doc)) {
    throw new Error("DID document is not a JSON object");
  }
  const did = doc as unknown as DidDocument;
  const methods = did.verificationMethod;
  if (!Array.isArray(methods) || methods.length === 0) {
    throw new Error("DID document has no verificationMethod entries");
  }

  // Prefer the method referenced by assertionMethod (the role used to attest
  // identity claims); fall back to the first Ed25519 verification method.
  const preferredId = pickAssertionMethodId(did);
  const method =
    methods.find((m) => preferredId !== null && m.id === preferredId) ??
    methods.find((m) => ED25519_TYPES.has(m.type));

  if (method === undefined) {
    throw new Error("DID document has no supported verification method");
  }

  if (typeof method.publicKeyMultibase === "string") {
    return {
      publicKey: decodeEd25519Multibase(method.publicKeyMultibase),
      algorithm: "ed25519",
    };
  }
  if (
    isRecord(method.publicKeyJwk) &&
    method.publicKeyJwk.kty === "OKP" &&
    method.publicKeyJwk.crv === "Ed25519" &&
    typeof method.publicKeyJwk.x === "string"
  ) {
    return {
      publicKey: base64UrlDecode(method.publicKeyJwk.x),
      algorithm: "ed25519",
    };
  }
  if (isRecord(method.publicKeyJwk) && method.publicKeyJwk.kty === "EC") {
    const point = p256PointFromJwk(method.publicKeyJwk);
    if (point === undefined) {
      throw new Error("DID verification method has a malformed EC P-256 JWK");
    }
    return { publicKey: point, algorithm: "ecdsa-p256-sha256" };
  }
  throw new Error(
    "DID verification method has neither publicKeyMultibase nor an Ed25519 or EC P-256 JWK",
  );
}

function pickAssertionMethodId(did: DidDocument): string | null {
  if (!Array.isArray(did.assertionMethod)) return null;
  for (const entry of did.assertionMethod) {
    if (typeof entry === "string") return entry;
    if (isRecord(entry) && typeof entry.id === "string") return entry.id;
  }
  return null;
}

// -----------------------------------------------------------------------------
// Encoding helpers.
// -----------------------------------------------------------------------------

const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function decodeEd25519Spki(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  if (body.length === 0) throw new Error("PEM body is empty");

  const der = new Uint8Array(Buffer.from(body, "base64"));
  if (der.byteLength !== ED25519_SPKI_PREFIX.byteLength + 32) {
    throw new Error(
      `unexpected SPKI length ${der.byteLength}; expected ${
        ED25519_SPKI_PREFIX.byteLength + 32
      } bytes for Ed25519`,
    );
  }
  for (let i = 0; i < ED25519_SPKI_PREFIX.byteLength; i++) {
    if (der[i] !== ED25519_SPKI_PREFIX[i]) {
      throw new Error("SPKI prefix does not match Ed25519 algorithm OID");
    }
  }
  return der.slice(ED25519_SPKI_PREFIX.byteLength);
}

const MULTICODEC_ED25519_PUB = new Uint8Array([0xed, 0x01]);

function decodeEd25519Multibase(mb: string): Uint8Array {
  if (!mb.startsWith("z")) {
    throw new Error(`unsupported multibase prefix in ${mb}`);
  }
  const bytes = base58btcDecode(mb.slice(1));
  if (
    bytes.byteLength !== 34 ||
    bytes[0] !== MULTICODEC_ED25519_PUB[0] ||
    bytes[1] !== MULTICODEC_ED25519_PUB[1]
  ) {
    throw new Error("multibase value is not an Ed25519 multicodec key");
  }
  return bytes.slice(2);
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcDecode(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array(0);
  const bytes: number[] = [0];
  for (const ch of s) {
    const value = BASE58_ALPHABET.indexOf(ch);
    if (value < 0) throw new Error(`invalid base58 character: ${ch}`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Each leading '1' encodes a leading zero byte.
  let leadingZeros = 0;
  for (const ch of s) {
    if (ch === "1") leadingZeros++;
    else break;
  }
  const out = new Uint8Array(leadingZeros + bytes.length);
  for (let i = 0; i < leadingZeros; i++) out[i] = 0;
  for (let i = 0; i < bytes.length; i++) {
    out[leadingZeros + i] = bytes[bytes.length - 1 - i]!;
  }
  return out;
}

function base64UrlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  return new Uint8Array(Buffer.from(padded + pad, "base64"));
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
