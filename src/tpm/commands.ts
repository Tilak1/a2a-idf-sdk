// Raw TPM2_Certify command construction and response parsing.
//
// Stock `tpm2_certify` (5.7) has no qualifying-data option and hardcodes the
// attestation's extraData to 00ff55aa, so the relying party's nonce cannot be
// carried through it. The nonce must be INSIDE the signed structure, so the
// host builds the command itself and sends it with `tpm2_send`.
//
// Layouts follow TCG TPM 2.0 Library, Part 3 (Commands) §18.2 and Part 1
// (Architecture) for the command/response framing. Integers are big-endian.

import { TpmFormatError, TPM_ALG_ECDSA, TPM_ALG_SHA256 } from "./structures.js";

export const TPM_ST_SESSIONS = 0x8002;
export const TPM_ST_NO_SESSIONS = 0x8001;
export const TPM_CC_CERTIFY = 0x00000148;
export const TPM_RS_PW = 0x40000009;
export const TPM_RC_SUCCESS = 0;

/** TPM2B_DATA holds at most the size of the largest digest (SHA-512). */
export const MAX_QUALIFYING_DATA_BYTES = 64;

export class TpmCommandError extends Error {
  constructor(
    message: string,
    readonly responseCode?: number,
  ) {
    super(message);
    this.name = "TpmCommandError";
  }
}

class Writer {
  private readonly out: number[] = [];
  u8(n: number): this {
    this.out.push(n & 0xff);
    return this;
  }
  u16(n: number): this {
    return this.u8(n >> 8).u8(n);
  }
  u32(n: number): this {
    return this.u16(n >>> 16).u16(n & 0xffff);
  }
  bytes(b: Uint8Array): this {
    for (const x of b) this.out.push(x);
    return this;
  }
  tpm2b(b: Uint8Array): this {
    return this.u16(b.byteLength).bytes(b);
  }
  toBytes(): Uint8Array {
    return Uint8Array.from(this.out);
  }
}

/**
 * TPM2_Certify: `signHandle` (the AK) certifies `objectHandle` (the signing
 * key), with `qualifyingData` copied into the signed attestation. Both objects
 * authorize with an empty-password session, which matches keys created
 * without an auth value. The AK signs with ECDSA/SHA-256.
 */
export function buildCertifyCommand(
  objectHandle: number,
  signHandle: number,
  qualifyingData: Uint8Array,
): Uint8Array {
  if (qualifyingData.byteLength > MAX_QUALIFYING_DATA_BYTES) {
    throw new RangeError(
      `qualifyingData exceeds ${MAX_QUALIFYING_DATA_BYTES} bytes`,
    );
  }
  const passwordSession = new Writer()
    .u32(TPM_RS_PW)
    .u16(0) // nonce
    .u8(0) // sessionAttributes
    .u16(0) // hmac (empty password)
    .toBytes();
  const body = new Writer()
    .u32(objectHandle)
    .u32(signHandle)
    .u32(passwordSession.byteLength * 2)
    .bytes(passwordSession)
    .bytes(passwordSession)
    .tpm2b(qualifyingData)
    .u16(TPM_ALG_ECDSA) // inScheme.scheme
    .u16(TPM_ALG_SHA256) // inScheme.details.hashAlg
    .toBytes();
  return new Writer()
    .u16(TPM_ST_SESSIONS)
    .u32(10 + body.byteLength)
    .u32(TPM_CC_CERTIFY)
    .bytes(body)
    .toBytes();
}

export interface CertifyResponse {
  /** TPMS_ATTEST bytes (the TPM2B_ATTEST payload). */
  certInfo: Uint8Array;
  /** TPMT_SIGNATURE bytes over `certInfo`. */
  certSignature: Uint8Array;
}

/** Splits a TPM2_Certify response; throws TpmCommandError on a TPM error. */
export function parseCertifyResponse(resp: Uint8Array): CertifyResponse {
  const dv = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
  if (resp.byteLength < 10) throw new TpmFormatError("TPM response truncated");
  const tag = dv.getUint16(0);
  const size = dv.getUint32(2);
  const rc = dv.getUint32(6);
  if (size !== resp.byteLength) {
    throw new TpmFormatError("TPM response size field does not match its length");
  }
  if (rc !== TPM_RC_SUCCESS) {
    throw new TpmCommandError(
      `TPM2_Certify failed with response code 0x${rc.toString(16)}`,
      rc,
    );
  }
  if (tag !== TPM_ST_SESSIONS) {
    throw new TpmFormatError(`unexpected response tag 0x${tag.toString(16)}`);
  }
  // No response handles; then parameterSize, parameters, auth area.
  if (resp.byteLength < 14) throw new TpmFormatError("TPM response truncated");
  const paramSize = dv.getUint32(10);
  if (14 + paramSize > resp.byteLength) {
    throw new TpmFormatError("TPM response parameter area truncated");
  }
  const params = resp.subarray(14, 14 + paramSize);
  if (params.byteLength < 2) throw new TpmFormatError("TPM response truncated");
  const attestSize = (params[0]! << 8) | params[1]!;
  if (2 + attestSize > params.byteLength) {
    throw new TpmFormatError("TPM2B_ATTEST truncated");
  }
  return {
    certInfo: params.slice(2, 2 + attestSize),
    certSignature: params.slice(2 + attestSize),
  };
}
