// Binding verification for TPM2_Certify evidence on the P-256 hardware-key
// path. Given an evidence bundle, it checks that the key a signer presents
// (a JWK, e.g. from the DID document at the keyid URL) is the TPM-resident
// key that a pinned attestation key (AK) certified for this challenge.
//
// Checks, in order:
//   1. The AK's ECDSA signature over the TPMS_ATTEST verifies (so every field
//      below is TPM-attested and not attacker-chosen).
//   2. The certified key is a P-256 ECC key.
//   3. The TPM name recomputed from the TPM2B_PUBLIC equals the certified name
//      inside the signed TPMS_ATTEST.
//   4. The key is non-exportable and TPM-generated: fixedTPM, fixedParent,
//      sensitiveDataOrigin and sign are set.
//   5. The nonce inside the signed structure (extraData) equals the nonce the
//      relying party issued.
//   6. The key's X and Y equal those of the supplied JWK.
//
// Limitations of this first version:
//   - The AK is pinned as the trust anchor. There is no EK certificate chain
//     and no TPM2_ActivateCredential, so nothing proves the AK itself lives in
//     the same TPM, or in a genuine TPM at all. Whoever controls the pinned AK
//     can certify any key.
//   - Nonce freshness is not checked here: the caller must issue nonces that
//     are single-use and short-lived, and pass the one it issued.
//   - The TPM in the reference setup is a virtual (software) TPM, which proves
//     the flow and does not resist a physical attacker.

import {
  createPublicKey,
  timingSafeEqual,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";

import { EcdsaEncodingError, P256_COORD_BYTES } from "./der.js";
import {
  ObjectAttributes,
  TPM_ALG_SHA256,
  TPM_ECC_NIST_P256,
  TpmFormatError,
  computeTpmName,
  hasObjectAttributes,
  parseCertifyAttest,
  parseTpm2bPublic,
  parseTpmtSignatureEcdsa,
  tpmtSignatureToRaw,
  type TpmCertifyAttest,
  type TpmEccPublic,
} from "./structures.js";

export interface TpmEvidence {
  /** TPMS_ATTEST bytes from TPM2_Certify (`tpm2_certify -o`). */
  certInfo: Uint8Array;
  /** TPMT_SIGNATURE by the AK over `certInfo` (`tpm2_certify -s`, tss format). */
  certSignature: Uint8Array;
  /** TPM2B_PUBLIC of the certified signing key (`tpm2_readpublic -o`). */
  keyPublic: Uint8Array;
}

export interface EcP256Jwk {
  kty?: string;
  crv?: string;
  x?: string;
  y?: string;
}

export interface VerifyBindingInputs {
  evidence: TpmEvidence;
  /** The pinned AK public key: a KeyObject or an SPKI PEM string. */
  akPublicKey: KeyObject | string;
  /** The nonce the relying party issued for this challenge. Must be non-empty. */
  expectedNonce: Uint8Array;
  /** The key the signer publishes, to be matched against the certified key. */
  jwk: EcP256Jwk;
}

export type BindingFailureReason =
  | "malformed-evidence"
  | "unsupported-signature-algorithm"
  | "ak-signature-invalid"
  | "unsupported-key-curve"
  | "name-mismatch"
  | "key-not-hardware-bound"
  | "nonce-mismatch"
  | "jwk-malformed"
  | "jwk-mismatch";

export type BindingResult =
  | { ok: true; key: TpmEccPublic; attest: TpmCertifyAttest }
  | { ok: false; reason: BindingFailureReason };

const fail = (reason: BindingFailureReason): BindingResult => ({
  ok: false,
  reason,
});

const equalBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.byteLength === b.byteLength && timingSafeEqual(a, b);

function loadAkPublicKey(input: KeyObject | string): KeyObject {
  const key = typeof input === "string" ? createPublicKey(input) : input;
  if (
    key.type !== "public" ||
    key.asymmetricKeyType !== "ec" ||
    key.asymmetricKeyDetails?.namedCurve !== "prime256v1"
  ) {
    throw new TypeError("akPublicKey must be an EC P-256 public key");
  }
  return key;
}

const leftPad32 = (v: Uint8Array): Uint8Array | undefined => {
  if (v.byteLength > P256_COORD_BYTES) return undefined;
  const out = new Uint8Array(P256_COORD_BYTES);
  out.set(v, P256_COORD_BYTES - v.byteLength);
  return out;
};

/** Strict unpadded base64url for a 32-byte coordinate (43 characters). */
function decodeJwkCoordinate(s: unknown): Uint8Array | undefined {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(s)) return undefined;
  const out = new Uint8Array(Buffer.from(s, "base64url"));
  return out.byteLength === P256_COORD_BYTES ? out : undefined;
}

/**
 * Verifies that `evidence` binds the challenge nonce to a hardware-resident
 * P-256 key equal to `jwk`, under the pinned AK. Malformed or hostile
 * evidence yields `{ ok: false }`; only caller misconfiguration (a bad AK or
 * an empty nonce) throws.
 */
export function verifyTpmBinding(inputs: VerifyBindingInputs): BindingResult {
  const { evidence, expectedNonce, jwk } = inputs;
  if (expectedNonce.byteLength === 0) {
    throw new TypeError("expectedNonce must not be empty");
  }
  const akKey = loadAkPublicKey(inputs.akPublicKey);

  let rawSignature: Uint8Array;
  let key: TpmEccPublic;
  try {
    const sig = parseTpmtSignatureEcdsa(evidence.certSignature);
    if (sig.hashAlg !== TPM_ALG_SHA256) {
      return fail("unsupported-signature-algorithm");
    }
    rawSignature = tpmtSignatureToRaw(evidence.certSignature);
    key = parseTpm2bPublic(evidence.keyPublic);
  } catch (e) {
    if (e instanceof TpmFormatError || e instanceof EcdsaEncodingError) {
      return fail("malformed-evidence");
    }
    throw e;
  }

  const signatureOk = cryptoVerify(
    "sha256",
    evidence.certInfo,
    { key: akKey, dsaEncoding: "ieee-p1363" },
    rawSignature,
  );
  if (!signatureOk) return fail("ak-signature-invalid");

  // The attest is now authentic; parsing it can still fail if the AK signed
  // something other than a well-formed certify structure.
  let attest: TpmCertifyAttest;
  let name: Uint8Array;
  try {
    attest = parseCertifyAttest(evidence.certInfo);
    name = computeTpmName(key);
  } catch (e) {
    if (e instanceof TpmFormatError) return fail("malformed-evidence");
    throw e;
  }

  if (key.curveId !== TPM_ECC_NIST_P256) return fail("unsupported-key-curve");
  if (!equalBytes(name, attest.certifiedName)) return fail("name-mismatch");

  const required =
    ObjectAttributes.fixedTPM |
    ObjectAttributes.fixedParent |
    ObjectAttributes.sensitiveDataOrigin |
    ObjectAttributes.sign;
  if (!hasObjectAttributes(key.objectAttributes, required)) {
    return fail("key-not-hardware-bound");
  }

  if (!equalBytes(attest.extraData, expectedNonce)) {
    return fail("nonce-mismatch");
  }

  if (jwk.kty !== "EC" || jwk.crv !== "P-256") return fail("jwk-malformed");
  const jx = decodeJwkCoordinate(jwk.x);
  const jy = decodeJwkCoordinate(jwk.y);
  if (!jx || !jy) return fail("jwk-malformed");
  const kx = leftPad32(key.x);
  const ky = leftPad32(key.y);
  if (!kx || !ky) return fail("malformed-evidence");
  if (!equalBytes(kx, jx) || !equalBytes(ky, jy)) return fail("jwk-mismatch");

  return { ok: true, key, attest };
}
