import { describe, it, expect } from "vitest";

import {
  MAX_QUALIFYING_DATA_BYTES,
  TPM_CC_CERTIFY,
  TpmCommandError,
  buildCertifyCommand,
  parseCertifyResponse,
} from "../../src/tpm/commands.js";
import { TpmFormatError } from "../../src/tpm/structures.js";
import { fx, hex, nonce, u16, u32 } from "./helpers.js";

const hexOf = (b: Uint8Array): string => Buffer.from(b).toString("hex");

describe("buildCertifyCommand", () => {
  it("frames TPM2_Certify with two password sessions and the nonce", () => {
    const cmd = buildCertifyCommand(0x81010011, 0x81010010, nonce);
    expect(hexOf(cmd)).toBe(
      "8002" + // TPM_ST_SESSIONS
        (10 + 8 + 4 + 18 + 2 + 32 + 4).toString(16).padStart(8, "0") +
        "00000148" +
        "81010011" + // objectHandle: the signing key
        "81010010" + // signHandle: the AK
        "00000012" + // authorizationSize = 18
        "40000009" + "0000" + "00" + "0000" +
        "40000009" + "0000" + "00" + "0000" +
        "0020" + fx.nonce + // qualifyingData
        "0018" + "000b", // ECDSA / SHA-256
    );
    expect(new DataView(cmd.buffer).getUint32(2)).toBe(cmd.byteLength);
    expect(new DataView(cmd.buffer).getUint32(6)).toBe(TPM_CC_CERTIFY);
  });

  it("rejects qualifying data larger than a TPM2B_DATA digest", () => {
    expect(() =>
      buildCertifyCommand(1, 2, new Uint8Array(MAX_QUALIFYING_DATA_BYTES + 1)),
    ).toThrow(RangeError);
    expect(buildCertifyCommand(1, 2, new Uint8Array(MAX_QUALIFYING_DATA_BYTES))).toBeTruthy();
  });
});

describe("parseCertifyResponse", () => {
  const certInfo = hex(fx.certInfo);
  const sig = hex(fx.certSigTss);
  const response = (over: { rc?: number; auth?: number[] } = {}): Uint8Array => {
    const params = [...u16(certInfo.length), ...certInfo, ...sig];
    const auth = over.auth ?? [0, 0, 0, 0, 0, 0, 0]; // one empty TPMS_AUTH_RESPONSE
    const body = [...u32(params.length), ...params, ...auth];
    return Uint8Array.from([
      ...u16(0x8002),
      ...u32(10 + body.length),
      ...u32(over.rc ?? 0),
      ...body,
    ]);
  };

  it("splits the attest structure and signature, ignoring the auth area", () => {
    const r = parseCertifyResponse(response());
    expect(hexOf(r.certInfo)).toBe(fx.certInfo);
    expect(hexOf(r.certSignature)).toBe(fx.certSigTss);
  });

  it("surfaces a TPM error code", () => {
    const err = Uint8Array.from([...u16(0x8001), ...u32(10), ...u32(0x9a2)]);
    expect(() => parseCertifyResponse(err)).toThrow(TpmCommandError);
    try {
      parseCertifyResponse(err);
    } catch (e) {
      expect((e as TpmCommandError).responseCode).toBe(0x9a2);
    }
  });

  it("rejects truncated and inconsistent responses", () => {
    const full = response();
    for (const n of [0, 5, 9, 13, 20, full.length - 30]) {
      expect(() => parseCertifyResponse(full.subarray(0, n)), `prefix ${n}`).toThrow();
    }
    const wrongSize = Uint8Array.from(full);
    wrongSize[5] ^= 1;
    expect(() => parseCertifyResponse(wrongSize)).toThrow(TpmFormatError);
  });
});
