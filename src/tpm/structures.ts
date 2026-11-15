// Strict parsers for the TPM 2.0 structures the hardware-key path consumes:
// TPMT_PUBLIC / TPM2B_PUBLIC, TPMS_ATTEST (TPM2_Certify result) and
// TPMT_SIGNATURE (ECDSA). Layouts follow TCG TPM 2.0 Library, Part 2
// (Structures); all integers are big-endian. Every parser rejects truncated
// input and trailing bytes: these bytes are attacker-supplied evidence.

import { sha256 } from "@noble/hashes/sha256";
import { sha384, sha512 } from "@noble/hashes/sha512";

import { rsToRaw } from "./der.js";

export const TPM_GENERATED_VALUE = 0xff544347;
export const TPM_ST_ATTEST_CERTIFY = 0x8017;

export const TPM_ALG_ECC = 0x0023;
export const TPM_ALG_ECDSA = 0x0018;
export const TPM_ALG_ECDAA = 0x001a;
export const TPM_ALG_NULL = 0x0010;
export const TPM_ALG_SHA256 = 0x000b;
export const TPM_ALG_SHA384 = 0x000c;
export const TPM_ALG_SHA512 = 0x000d;
export const TPM_ECC_NIST_P256 = 0x0003;

/** TPMA_OBJECT bit masks (Part 2, §8.3.2). */
export const ObjectAttributes = {
  fixedTPM: 1 << 1,
  fixedParent: 1 << 4,
  sensitiveDataOrigin: 1 << 5,
  userWithAuth: 1 << 6,
  restricted: 1 << 16,
  decrypt: 1 << 17,
  sign: 1 << 18,
} as const;

export class TpmFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TpmFormatError";
  }
}

class Reader {
  private pos = 0;
  constructor(
    private readonly buf: Uint8Array,
    private readonly what: string,
  ) {}

  bytes(n: number): Uint8Array {
    if (n < 0 || this.pos + n > this.buf.byteLength) {
      throw new TpmFormatError(`${this.what} truncated`);
    }
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  u8(): number {
    return this.bytes(1)[0]!;
  }

  u16(): number {
    const b = this.bytes(2);
    return (b[0]! << 8) | b[1]!;
  }

  u32(): number {
    const b = this.bytes(4);
    return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
  }

  u64(): bigint {
    const hi = BigInt(this.u32());
    const lo = BigInt(this.u32());
    return (hi << 32n) | lo;
  }

  /** TPM2B_*: u16 size followed by that many bytes. */
  tpm2b(): Uint8Array {
    return this.bytes(this.u16());
  }

  done(): void {
    if (this.pos !== this.buf.byteLength) {
      throw new TpmFormatError(`trailing bytes after ${this.what}`);
    }
  }
}

// --- TPMT_PUBLIC / TPM2B_PUBLIC (ECC keys only) ---------------------------

export interface TpmEccPublic {
  nameAlg: number;
  objectAttributes: number;
  authPolicy: Uint8Array;
  /** TPMT_SYM_DEF_OBJECT algorithm; TPM_ALG_NULL for signing keys. */
  symmetricAlg: number;
  /** TPMT_ECC_SCHEME scheme; TPM_ALG_NULL when chosen at sign time. */
  schemeAlg: number;
  schemeHashAlg?: number;
  curveId: number;
  x: Uint8Array;
  y: Uint8Array;
  /** The exact TPMT_PUBLIC bytes; the TPM name is a hash of these. */
  tpmtPublic: Uint8Array;
}

/** Parses a TPMT_PUBLIC. Only ECC public areas are supported. */
export function parseTpmtPublic(tpmtPublic: Uint8Array): TpmEccPublic {
  const r = new Reader(tpmtPublic, "TPMT_PUBLIC");
  const type = r.u16();
  if (type !== TPM_ALG_ECC) {
    throw new TpmFormatError(
      `unsupported public area type 0x${type.toString(16)}, expected ECC`,
    );
  }
  const nameAlg = r.u16();
  const objectAttributes = r.u32();
  const authPolicy = r.tpm2b();

  const symmetricAlg = r.u16();
  if (symmetricAlg !== TPM_ALG_NULL) {
    r.u16(); // keyBits
    r.u16(); // mode
  }

  const schemeAlg = r.u16();
  let schemeHashAlg: number | undefined;
  if (schemeAlg !== TPM_ALG_NULL) {
    schemeHashAlg = r.u16();
    if (schemeAlg === TPM_ALG_ECDAA) r.u16(); // count
  }

  const curveId = r.u16();
  const kdfAlg = r.u16();
  if (kdfAlg !== TPM_ALG_NULL) r.u16(); // kdf hashAlg

  const x = r.tpm2b();
  const y = r.tpm2b();
  r.done();

  return {
    nameAlg,
    objectAttributes,
    authPolicy,
    symmetricAlg,
    schemeAlg,
    ...(schemeHashAlg !== undefined ? { schemeHashAlg } : {}),
    curveId,
    x,
    y,
    tpmtPublic,
  };
}

/** Parses a TPM2B_PUBLIC (u16 size prefix + TPMT_PUBLIC). */
export function parseTpm2bPublic(tpm2bPublic: Uint8Array): TpmEccPublic {
  const r = new Reader(tpm2bPublic, "TPM2B_PUBLIC");
  const inner = r.tpm2b();
  r.done();
  return parseTpmtPublic(inner);
}

function hashFor(alg: number): (data: Uint8Array) => Uint8Array {
  switch (alg) {
    case TPM_ALG_SHA256:
      return sha256;
    case TPM_ALG_SHA384:
      return sha384;
    case TPM_ALG_SHA512:
      return sha512;
    default:
      throw new TpmFormatError(
        `unsupported name algorithm 0x${alg.toString(16)}`,
      );
  }
}

/**
 * Computes the TPM object name: nameAlg (u16) || H_nameAlg(TPMT_PUBLIC).
 * The hash covers the TPMT_PUBLIC only, not the TPM2B size prefix.
 */
export function computeTpmName(pub: TpmEccPublic): Uint8Array {
  const digest = hashFor(pub.nameAlg)(pub.tpmtPublic);
  const name = new Uint8Array(2 + digest.length);
  name[0] = pub.nameAlg >> 8;
  name[1] = pub.nameAlg & 0xff;
  name.set(digest, 2);
  return name;
}

export function hasObjectAttributes(
  attributes: number,
  mask: number,
): boolean {
  return (attributes & mask) === mask;
}

// --- TPMS_ATTEST (TPM2_Certify) -------------------------------------------

export interface TpmCertifyAttest {
  qualifiedSigner: Uint8Array;
  /** qualifyingData supplied to TPM2_Certify; carries the RP's nonce. */
  extraData: Uint8Array;
  clock: bigint;
  resetCount: number;
  restartCount: number;
  safe: boolean;
  firmwareVersion: bigint;
  /** Name of the certified object. */
  certifiedName: Uint8Array;
  certifiedQualifiedName: Uint8Array;
}

/** Parses a TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY. */
export function parseCertifyAttest(attest: Uint8Array): TpmCertifyAttest {
  const r = new Reader(attest, "TPMS_ATTEST");
  const magic = r.u32();
  if (magic !== TPM_GENERATED_VALUE) {
    throw new TpmFormatError("TPMS_ATTEST magic is not TPM_GENERATED_VALUE");
  }
  const type = r.u16();
  if (type !== TPM_ST_ATTEST_CERTIFY) {
    throw new TpmFormatError(
      `TPMS_ATTEST type 0x${type.toString(16)} is not a certify attestation`,
    );
  }
  const qualifiedSigner = r.tpm2b();
  const extraData = r.tpm2b();
  const clock = r.u64();
  const resetCount = r.u32();
  const restartCount = r.u32();
  const safe = r.u8() !== 0;
  const firmwareVersion = r.u64();
  const certifiedName = r.tpm2b();
  const certifiedQualifiedName = r.tpm2b();
  r.done();

  return {
    qualifiedSigner,
    extraData,
    clock,
    resetCount,
    restartCount,
    safe,
    firmwareVersion,
    certifiedName,
    certifiedQualifiedName,
  };
}

// --- TPMT_SIGNATURE (ECDSA) ------------------------------------------------

export interface TpmEcdsaSignature {
  hashAlg: number;
  r: Uint8Array;
  s: Uint8Array;
}

/** Parses a TPMT_SIGNATURE holding an ECDSA signature (tpm2-tools `-f tss`). */
export function parseTpmtSignatureEcdsa(sig: Uint8Array): TpmEcdsaSignature {
  const reader = new Reader(sig, "TPMT_SIGNATURE");
  const alg = reader.u16();
  if (alg !== TPM_ALG_ECDSA) {
    throw new TpmFormatError(
      `unsupported signature algorithm 0x${alg.toString(16)}, expected ECDSA`,
    );
  }
  const hashAlg = reader.u16();
  const r = reader.tpm2b();
  const s = reader.tpm2b();
  reader.done();
  return { hashAlg, r, s };
}

/**
 * Raw r || s (64 bytes for P-256) from a TPMT_SIGNATURE. The TPM may return
 * r or s with leading zeros stripped, so each is left-padded to 32 bytes.
 */
export function tpmtSignatureToRaw(sig: Uint8Array): Uint8Array {
  const { r, s } = parseTpmtSignatureEcdsa(sig);
  return rsToRaw(r, s);
}
