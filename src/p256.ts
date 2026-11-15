// P-256 public key helpers shared by the RFC 9421 ecdsa-p256-sha256 verifier
// and the keyid resolver. A P-256 public key is carried as a 65-byte SEC1
// uncompressed point (0x04 || X || Y), the P-256 analogue of the 32-byte raw
// Ed25519 key used elsewhere in the SDK.

import { createPublicKey, type KeyObject } from "node:crypto";

export const P256_POINT_BYTES = 65;
const COORD_BYTES = 32;

export interface P256Jwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}

/** Strict unpadded base64url for a 32-byte coordinate (43 characters). */
function decodeCoordinate(s: unknown): Uint8Array | undefined {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(s)) return undefined;
  const out = new Uint8Array(Buffer.from(s, "base64url"));
  return out.byteLength === COORD_BYTES ? out : undefined;
}

/**
 * The uncompressed point for an EC P-256 JWK, or undefined if `jwk` is not a
 * well-formed P-256 public JWK whose point lies on the curve.
 */
export function p256PointFromJwk(jwk: unknown): Uint8Array | undefined {
  if (typeof jwk !== "object" || jwk === null) return undefined;
  const j = jwk as Record<string, unknown>;
  if (j["kty"] !== "EC" || j["crv"] !== "P-256") return undefined;
  const x = decodeCoordinate(j["x"]);
  const y = decodeCoordinate(j["y"]);
  if (!x || !y) return undefined;
  const point = new Uint8Array(P256_POINT_BYTES);
  point[0] = 0x04;
  point.set(x, 1);
  point.set(y, 1 + COORD_BYTES);
  return p256PublicKeyFromPoint(point) === undefined ? undefined : point;
}

/** The JWK form of an uncompressed P-256 point, e.g. to feed binding checks. */
export function p256JwkFromPoint(point: Uint8Array): P256Jwk {
  if (point.byteLength !== P256_POINT_BYTES || point[0] !== 0x04) {
    throw new TypeError("expected a 65-byte uncompressed P-256 point");
  }
  return {
    kty: "EC",
    crv: "P-256",
    x: Buffer.from(point.subarray(1, 1 + COORD_BYTES)).toString("base64url"),
    y: Buffer.from(point.subarray(1 + COORD_BYTES)).toString("base64url"),
  };
}

/** A KeyObject for an uncompressed point; undefined if it is not on the curve. */
export function p256PublicKeyFromPoint(point: Uint8Array): KeyObject | undefined {
  if (point.byteLength !== P256_POINT_BYTES || point[0] !== 0x04) return undefined;
  try {
    return createPublicKey({
      key: {
        kty: "EC",
        crv: "P-256",
        x: Buffer.from(point.subarray(1, 1 + COORD_BYTES)).toString("base64url"),
        y: Buffer.from(point.subarray(1 + COORD_BYTES)).toString("base64url"),
      },
      format: "jwk",
    });
  } catch {
    return undefined;
  }
}

/** The uncompressed point of a P-256 public KeyObject; undefined for others. */
export function p256PointFromKey(key: KeyObject): Uint8Array | undefined {
  if (key.type !== "public" || key.asymmetricKeyType !== "ec") return undefined;
  if (key.asymmetricKeyDetails?.namedCurve !== "prime256v1") return undefined;
  return p256PointFromJwk(key.export({ format: "jwk" }));
}
