import { readFileSync } from "node:fs";
import {
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";

import type { EcP256Jwk, TpmEvidence } from "../../src/tpm/binding.js";
import {
  TPM_ALG_ECDSA,
  TPM_ALG_SHA256,
  TPM_GENERATED_VALUE,
  TPM_ST_ATTEST_CERTIFY,
  computeTpmName,
  parseTpm2bPublic,
} from "../../src/tpm/structures.js";

export const fx = JSON.parse(
  readFileSync(new URL("./fixtures/vtpm-p256.json", import.meta.url), "utf8"),
);
export const hex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, "hex"));
export const jwkOf = (pem: string): EcP256Jwk =>
  createPublicKey(pem).export({ format: "jwk" }) as EcP256Jwk;

export const nonce = hex(fx.nonce);
export const keyJwk = jwkOf(fx.keyPem);
export const realEvidence: TpmEvidence = {
  certInfo: hex(fx.certInfo),
  certSignature: hex(fx.certSigTss),
  keyPublic: hex(fx.keyPub),
};

// --- helpers to build AK-signed evidence with chosen contents -------------

export const u16 = (n: number): number[] => [(n >> 8) & 0xff, n & 0xff];
export const u32 = (n: number): number[] => [...u16(n >>> 16), ...u16(n & 0xffff)];
export const tpm2b = (b: Uint8Array): number[] => [...u16(b.length), ...b];

export function buildAttest(extraData: Uint8Array, certifiedName: Uint8Array): Uint8Array {
  return Uint8Array.from([
    ...u32(TPM_GENERATED_VALUE),
    ...u16(TPM_ST_ATTEST_CERTIFY),
    ...tpm2b(new Uint8Array(34).fill(1)), // qualifiedSigner
    ...tpm2b(extraData),
    ...new Array(8).fill(0), // clock
    ...u32(1), // resetCount
    ...u32(2), // restartCount
    1, // safe
    ...new Array(8).fill(0), // firmwareVersion
    ...tpm2b(certifiedName),
    ...tpm2b(certifiedName), // certifiedQualifiedName
  ]);
}

export function tpmtSignature(raw: Uint8Array, hashAlg = TPM_ALG_SHA256): Uint8Array {
  return Uint8Array.from([
    ...u16(TPM_ALG_ECDSA),
    ...u16(hashAlg),
    ...tpm2b(raw.subarray(0, 32)),
    ...tpm2b(raw.subarray(32)),
  ]);
}

export interface Synthetic {
  akPem: string;
  akKey: KeyObject;
  make(opts?: {
    keyPublic?: Uint8Array;
    extraData?: Uint8Array;
    certifiedName?: Uint8Array;
  }): TpmEvidence;
  /** Signs arbitrary bytes as if they were the Certify structure. */
  signCertInfo(certInfo: Uint8Array): TpmEvidence;
}

export function syntheticAk(): Synthetic {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const signCertInfo = (
    certInfo: Uint8Array,
    keyPublic = realEvidence.keyPublic,
  ): TpmEvidence => {
    const raw = cryptoSign("sha256", certInfo, {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    });
    return { certInfo, certSignature: tpmtSignature(raw), keyPublic };
  };
  return {
    akPem: publicKey.export({ format: "pem", type: "spki" }) as string,
    akKey: publicKey,
    make({ keyPublic = realEvidence.keyPublic, extraData = nonce, certifiedName } = {}) {
      const name = certifiedName ?? computeTpmName(parseTpm2bPublic(keyPublic));
      return signCertInfo(buildAttest(extraData, name), keyPublic);
    },
    signCertInfo,
  };
}

/** Returns a copy of the fixture TPM2B_PUBLIC with `edit` applied to it. */
export const editKeyPublic = (edit: (b: Uint8Array) => void): Uint8Array => {
  const b = Uint8Array.from(realEvidence.keyPublic);
  edit(b);
  return b;
};
// TPM2B_PUBLIC layout: size(2) type(2) nameAlg(2) objectAttributes(4) ...
export const ATTR_LOW_BYTE = 9;
export const CURVE_LOW_BYTE = 19;


/**
 * A TPM2B_PUBLIC (hardware-bound signing key attributes) for a P-256 point the
 * test holds the private key of. Reuses the fixture layout: x at 24..55, y at
 * 58..89.
 */
export function keyPublicForPoint(point: Uint8Array): Uint8Array {
  const out = Uint8Array.from(realEvidence.keyPublic);
  out.set(point.subarray(1, 33), 24);
  out.set(point.subarray(33, 65), 58);
  return out;
}
