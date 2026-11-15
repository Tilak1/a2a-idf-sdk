// RFC 9421 HTTP Message Signatures with alg="ecdsa-p256-sha256" (§3.3.4), the
// hardware-key (TPM) counterpart of the Ed25519 flow in ./rfc9421.ts.
//
// Differences from the Ed25519 profile, all strict:
//   - Covered components are exactly "@method" "@authority" "@path"
//     "content-digest", in that order. A verifier that accepted fewer would
//     let an attacker strip coverage.
//   - Parameters are exactly created;expires;keyid;alg;nonce[;tag], in that
//     order, and `alg` is signed and must be "ecdsa-p256-sha256".
//   - The signature value is raw r||s (64 bytes), never ASN.1 DER. TPM tools
//     emit DER or TPMT_SIGNATURE: convert with ./tpm/der.ts first.
//
// Signing takes a callback because the private key lives in the TPM and the
// SDK never sees it. The callback receives the signature base and must return
// the ECDSA/SHA-256 signature over it as raw r||s.
//
// A valid signature here proves possession of the P-256 key only. That the key
// is TPM-resident is established separately by ./tpm/challenge.ts.

import { timingSafeEqual, verify as cryptoVerify } from "node:crypto";

import { p256PublicKeyFromPoint } from "./p256.js";
import {
  computeContentDigest,
  type DigestAlgorithm,
  type SignedHeaders,
} from "./rfc9421.js";

export const ECDSA_P256_ALG = "ecdsa-p256-sha256";

const COMPONENTS = ["@method", "@authority", "@path", "content-digest"] as const;
const RAW_SIGNATURE_BYTES = 64;

export interface P256SignatureParams {
  /** Absolute URL resolving to the public key document. */
  keyid: string;
  /** Unix seconds at which the signature was created. */
  created: number;
  /** Unix seconds at which the signature stops being valid. */
  expires: number;
  /**
   * Per-request token. May be the relying party's challenge nonce so the same
   * value binds the HTTP request and the TPM evidence.
   */
  nonce: string;
  tag?: string;
}

export interface SignP256Inputs {
  method: string;
  /** The request authority (Host); lowercased as RFC 9421 §2.2.3 requires. */
  authority: string;
  /** Path (and query) portion of the request-target. */
  path: string;
  body: Uint8Array;
  digestAlgorithm?: DigestAlgorithm;
  params: P256SignatureParams;
}

/**
 * Signs the signature base with the P-256 key and returns raw r||s (64 bytes).
 * Returning a DER signature is rejected; see ./tpm/der.ts `derToRaw`.
 */
export type P256Signer = (message: Uint8Array) => Uint8Array | Promise<Uint8Array>;

export interface VerifyP256Inputs {
  method: string;
  authority: string;
  path: string;
  body: Uint8Array;
  headers: {
    "content-digest"?: string;
    "signature-input"?: string;
    signature?: string;
  };
  /** Uncompressed P-256 point (65 bytes), e.g. from `resolveKeyid`. */
  publicKey: Uint8Array;
  /** Defaults to 300s, the same as the Ed25519 verifier. */
  maxAgeSeconds?: number;
  /** Defaults to 30s, the same as the Ed25519 verifier. */
  maxSkewSeconds?: number;
  nowSeconds?: number;
  /** If set, the signed `nonce` parameter must equal it (challenge reuse). */
  expectedNonce?: string;
  /**
   * Optional replay callback, called only after the signature verifies. It
   * MUST return `false` if the nonce was seen before, `true` if first-seen.
   */
  checkNonce?: (nonce: string) => boolean;
}

export type P256VerifyFailureReason =
  | "missing-headers"
  | "malformed-signature-input"
  | "malformed-signature"
  | "algorithm-mismatch"
  | "content-digest-missing"
  | "content-digest-mismatch"
  | "content-digest-unsupported-algorithm"
  | "invalid-public-key"
  | "timestamp-too-old"
  | "timestamp-future-skew"
  | "signature-expired"
  | "nonce-mismatch"
  | "signature-invalid"
  | "replay-detected";

export type P256VerifyResult =
  | { ok: true; params: P256SignatureParams }
  | { ok: false; reason: P256VerifyFailureReason };

// Characters that would let a value escape its structured-field string or
// inject a line into the signature base.
const SAFE_STRING = /^[\x20\x21\x23-\x5b\x5d-\x7e]*$/;

function normalizeAuthority(authority: string): string {
  const a = authority.toLowerCase();
  if (a.length === 0 || !/^[a-z0-9._:\[\]-]+$/.test(a)) {
    throw new TypeError("authority must be a non-empty host[:port]");
  }
  return a;
}

function assertSafeLine(name: string, value: string): void {
  if (/[\r\n]/.test(value)) throw new TypeError(`${name} must not contain line breaks`);
}

function serializeParams(p: P256SignatureParams): string {
  const parts = [
    `created=${p.created}`,
    `expires=${p.expires}`,
    `keyid="${p.keyid}"`,
    `alg="${ECDSA_P256_ALG}"`,
    `nonce="${p.nonce}"`,
  ];
  if (p.tag !== undefined) parts.push(`tag="${p.tag}"`);
  return parts.join(";");
}

function serializeSignatureInput(p: P256SignatureParams): string {
  const list = COMPONENTS.map((c) => `"${c}"`).join(" ");
  return `sig1=(${list});${serializeParams(p)}`;
}

function buildBase(
  method: string,
  authority: string,
  path: string,
  contentDigest: string,
  p: P256SignatureParams,
): string {
  const list = COMPONENTS.map((c) => `"${c}"`).join(" ");
  return [
    `"@method": ${method.toUpperCase()}`,
    `"@authority": ${authority}`,
    `"@path": ${path}`,
    `"content-digest": ${contentDigest}`,
    `"@signature-params": (${list});${serializeParams(p)}`,
  ].join("\n");
}

function assertValidParams(p: P256SignatureParams): void {
  for (const [name, v] of [
    ["keyid", p.keyid],
    ["nonce", p.nonce],
    ["tag", p.tag],
  ] as const) {
    if (v !== undefined && !SAFE_STRING.test(v)) {
      throw new TypeError(`${name} contains characters not allowed in a signed string`);
    }
  }
  if (p.keyid.length === 0 || p.nonce.length === 0) {
    throw new TypeError("keyid and nonce must not be empty");
  }
  if (!Number.isSafeInteger(p.created) || !Number.isSafeInteger(p.expires)) {
    throw new TypeError("created and expires must be integer seconds");
  }
  if (p.expires <= p.created) throw new TypeError("expires must be after created");
}

export async function signEcdsaP256(
  inputs: SignP256Inputs,
  signer: P256Signer,
): Promise<SignedHeaders> {
  assertValidParams(inputs.params);
  assertSafeLine("method", inputs.method);
  assertSafeLine("path", inputs.path);
  const authority = normalizeAuthority(inputs.authority);
  const contentDigest = computeContentDigest(
    inputs.body,
    inputs.digestAlgorithm ?? "sha-256",
  );
  const base = buildBase(
    inputs.method,
    authority,
    inputs.path,
    contentDigest,
    inputs.params,
  );
  const signature = await signer(new TextEncoder().encode(base));
  if (signature.byteLength !== RAW_SIGNATURE_BYTES) {
    throw new TypeError(
      `signer must return ${RAW_SIGNATURE_BYTES} bytes of raw r||s, got ${signature.byteLength} ` +
        "(DER or TPMT_SIGNATURE output needs converting first)",
    );
  }
  return {
    "Content-Digest": contentDigest,
    "Signature-Input": serializeSignatureInput(inputs.params),
    Signature: `sig1=:${Buffer.from(signature).toString("base64")}:`,
  };
}

/**
 * Parses a Signature-Input header produced by `signEcdsaP256`. Returns null
 * for anything else, including any reordering, extra parameter or different
 * covered components: the header must re-serialize to exactly the input.
 */
export function parseP256SignatureInput(value: string): P256SignatureParams | null {
  const m =
    /^sig1=\("@method" "@authority" "@path" "content-digest"\);created=(\d{1,15});expires=(\d{1,15});keyid="([^"]*)";alg="ecdsa-p256-sha256";nonce="([^"]*)"(?:;tag="([^"]*)")?$/.exec(
      value,
    );
  if (m === null) return null;
  const params: P256SignatureParams = {
    keyid: m[3]!,
    created: Number(m[1]),
    expires: Number(m[2]),
    nonce: m[4]!,
    ...(m[5] !== undefined ? { tag: m[5] } : {}),
  };
  try {
    assertValidParams(params);
  } catch {
    return null;
  }
  return serializeSignatureInput(params) === value ? params : null;
}

function parseSignatureValue(value: string): Uint8Array | null {
  const m = /^sig1=:([A-Za-z0-9+/]+={0,2}):$/.exec(value);
  if (m === null) return null;
  const bytes = new Uint8Array(Buffer.from(m[1]!, "base64"));
  if (Buffer.from(bytes).toString("base64") !== m[1]) return null;
  return bytes;
}

export function verifyEcdsaP256(inputs: VerifyP256Inputs): P256VerifyResult {
  const sigInput = inputs.headers["signature-input"];
  const sigHeader = inputs.headers.signature;
  if (sigInput === undefined || sigHeader === undefined) {
    return { ok: false, reason: "missing-headers" };
  }

  // A different alg (e.g. a downgrade to Ed25519 naming) is reported as such
  // rather than as a generic parse failure.
  if (/;alg="/.test(sigInput) && !sigInput.includes(`alg="${ECDSA_P256_ALG}"`)) {
    return { ok: false, reason: "algorithm-mismatch" };
  }
  const params = parseP256SignatureInput(sigInput);
  if (params === null) return { ok: false, reason: "malformed-signature-input" };

  const signature = parseSignatureValue(sigHeader);
  if (signature === null || signature.byteLength !== RAW_SIGNATURE_BYTES) {
    return { ok: false, reason: "malformed-signature" };
  }

  const digestHeader = inputs.headers["content-digest"];
  if (digestHeader === undefined) {
    return { ok: false, reason: "content-digest-missing" };
  }
  const digestAlg: DigestAlgorithm | null = digestHeader.startsWith("sha-256=:")
    ? "sha-256"
    : digestHeader.startsWith("sha-512=:")
      ? "sha-512"
      : null;
  if (digestAlg === null) {
    return { ok: false, reason: "content-digest-unsupported-algorithm" };
  }
  const recomputed = Buffer.from(computeContentDigest(inputs.body, digestAlg));
  const advertised = Buffer.from(digestHeader);
  if (recomputed.length !== advertised.length || !timingSafeEqual(recomputed, advertised)) {
    return { ok: false, reason: "content-digest-mismatch" };
  }

  const key = p256PublicKeyFromPoint(inputs.publicKey);
  if (key === undefined) return { ok: false, reason: "invalid-public-key" };

  const maxAge = inputs.maxAgeSeconds ?? 300;
  const maxSkew = inputs.maxSkewSeconds ?? 30;
  const now = inputs.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (now - params.created > maxAge) return { ok: false, reason: "timestamp-too-old" };
  if (params.created - now > maxSkew) {
    return { ok: false, reason: "timestamp-future-skew" };
  }
  if (now >= params.expires) return { ok: false, reason: "signature-expired" };

  if (inputs.expectedNonce !== undefined && params.nonce !== inputs.expectedNonce) {
    return { ok: false, reason: "nonce-mismatch" };
  }

  let base: string;
  try {
    base = buildBase(
      inputs.method,
      normalizeAuthority(inputs.authority),
      inputs.path,
      digestHeader,
      params,
    );
  } catch {
    return { ok: false, reason: "signature-invalid" };
  }
  const ok = cryptoVerify(
    "sha256",
    new TextEncoder().encode(base),
    { key, dsaEncoding: "ieee-p1363" },
    signature,
  );
  if (!ok) return { ok: false, reason: "signature-invalid" };

  if (inputs.checkNonce !== undefined && !inputs.checkNonce(params.nonce)) {
    return { ok: false, reason: "replay-detected" };
  }
  return { ok: true, params };
}
