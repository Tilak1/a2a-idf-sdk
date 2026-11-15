import { readFileSync } from "node:fs";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { describe, it, expect } from "vitest";

import {
  ObjectAttributes,
  TPM_ECC_NIST_P256,
  TPM_ALG_SHA256,
  TPM_ALG_ECDSA,
  computeTpmName,
  hasObjectAttributes,
  parseCertifyAttest,
  parseTpm2bPublic,
  parseTpmtPublic,
  parseTpmtSignatureEcdsa,
  tpmtSignatureToRaw,
  TpmFormatError,
} from "../../src/tpm/structures.js";

const fx = JSON.parse(
  readFileSync(new URL("./fixtures/vtpm-p256.json", import.meta.url), "utf8"),
);
const hex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, "hex"));
const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");

describe("parseTpm2bPublic", () => {
  const pub = parseTpm2bPublic(hex(fx.keyPub));

  it("decodes the captured signing key", () => {
    expect(pub.curveId).toBe(TPM_ECC_NIST_P256);
    expect(pub.nameAlg).toBe(TPM_ALG_SHA256);
    expect(pub.x.length).toBe(32);
    expect(pub.y.length).toBe(32);
  });

  it("reports a non-exportable, unrestricted signing key", () => {
    const a = pub.objectAttributes;
    expect(hasObjectAttributes(a, ObjectAttributes.fixedTPM)).toBe(true);
    expect(hasObjectAttributes(a, ObjectAttributes.fixedParent)).toBe(true);
    expect(hasObjectAttributes(a, ObjectAttributes.sensitiveDataOrigin)).toBe(true);
    expect(hasObjectAttributes(a, ObjectAttributes.sign)).toBe(true);
    expect(hasObjectAttributes(a, ObjectAttributes.restricted)).toBe(false);
  });

  it("matches the x/y of the PEM exported by tpm2_readpublic", () => {
    const jwk = createPublicKey(fx.keyPem).export({ format: "jwk" });
    expect(b64u(pub.x)).toBe(jwk.x);
    expect(b64u(pub.y)).toBe(jwk.y);
  });

  it("rejects truncation, trailing bytes and a wrong size prefix", () => {
    const full = hex(fx.keyPub);
    for (let n = 0; n < full.length; n++) {
      expect(() => parseTpm2bPublic(full.subarray(0, n)), `prefix ${n}`).toThrow(
        TpmFormatError,
      );
    }
    expect(() => parseTpm2bPublic(Uint8Array.from([...full, 0]))).toThrow(TpmFormatError);
  });

  it("rejects non-ECC public areas", () => {
    const tpmt = hex(fx.keyPub).slice(2);
    tpmt[0] = 0x00;
    tpmt[1] = 0x01; // TPM_ALG_RSA
    expect(() => parseTpmtPublic(tpmt)).toThrow(/expected ECC/);
  });
});

describe("computeTpmName", () => {
  it("recomputes the name tpm2_load reported", () => {
    const name = computeTpmName(parseTpm2bPublic(hex(fx.keyPub)));
    expect(Buffer.from(name).toString("hex")).toBe(fx.keyName);
  });

  it("changes when any public-area byte changes", () => {
    const tampered = hex(fx.keyPub);
    tampered[tampered.length - 1] ^= 1; // flip a bit of y
    const name = computeTpmName(parseTpm2bPublic(tampered));
    expect(Buffer.from(name).toString("hex")).not.toBe(fx.keyName);
  });
});

describe("parseCertifyAttest", () => {
  const attest = parseCertifyAttest(hex(fx.certInfo));

  it("exposes the nonce that was passed as qualifyingData", () => {
    expect(Buffer.from(attest.extraData).toString("hex")).toBe(fx.nonce);
  });

  it("certifies the signing key by name", () => {
    expect(Buffer.from(attest.certifiedName).toString("hex")).toBe(fx.keyName);
  });

  it("rejects truncation and trailing bytes", () => {
    const full = hex(fx.certInfo);
    for (let n = 0; n < full.length; n++) {
      expect(() => parseCertifyAttest(full.subarray(0, n)), `prefix ${n}`).toThrow(
        TpmFormatError,
      );
    }
    expect(() => parseCertifyAttest(Uint8Array.from([...full, 0]))).toThrow(TpmFormatError);
  });

  it("rejects bad magic and non-certify types", () => {
    const badMagic = hex(fx.certInfo);
    badMagic[0] = 0;
    expect(() => parseCertifyAttest(badMagic)).toThrow(/TPM_GENERATED/);

    const quote = hex(fx.certInfo);
    quote[5] = 0x18; // TPM_ST_ATTEST_QUOTE
    expect(() => parseCertifyAttest(quote)).toThrow(/not a certify/);
  });

  it("carries a signature that verifies under the AK and not after tampering", () => {
    const raw = tpmtSignatureToRaw(hex(fx.certSigTss));
    const check = (data: Uint8Array): boolean =>
      cryptoVerify("sha256", data, { key: fx.akPem, dsaEncoding: "ieee-p1363" }, raw);
    expect(check(hex(fx.certInfo))).toBe(true);

    const tampered = hex(fx.certInfo);
    tampered[0x30] ^= 1;
    expect(check(tampered)).toBe(false);
  });
});

describe("TPMT_SIGNATURE", () => {
  it("parses the tpm2_sign default output and verifies as raw r||s", () => {
    const sig = parseTpmtSignatureEcdsa(hex(fx.sign.tss));
    expect(sig.hashAlg).toBe(TPM_ALG_SHA256);
    const raw = tpmtSignatureToRaw(hex(fx.sign.tss));
    expect(raw.length).toBe(64);
    expect(
      cryptoVerify(
        "sha256",
        new TextEncoder().encode("GET /x"),
        { key: fx.keyPem, dsaEncoding: "ieee-p1363" },
        raw,
      ),
    ).toBe(true);
  });

  it("left-pads an r that the TPM returned with leading zeros stripped", () => {
    const r = new Uint8Array(31).fill(0xaa);
    const s = new Uint8Array(32).fill(0xbb);
    const tpmt = Uint8Array.from([
      0x00, TPM_ALG_ECDSA, 0x00, TPM_ALG_SHA256,
      0x00, 31, ...r,
      0x00, 32, ...s,
    ]);
    const raw = tpmtSignatureToRaw(tpmt);
    expect(raw[0]).toBe(0);
    expect(raw.subarray(1, 32)).toEqual(r);
    expect(raw.subarray(32)).toEqual(s);
  });

  it("rejects other algorithms, truncation and trailing bytes", () => {
    const good = hex(fx.sign.tss);
    const rsassa = Uint8Array.from(good);
    rsassa[1] = 0x14; // TPM_ALG_RSASSA
    expect(() => parseTpmtSignatureEcdsa(rsassa)).toThrow(/expected ECDSA/);
    expect(() => parseTpmtSignatureEcdsa(good.subarray(0, good.length - 1))).toThrow(
      TpmFormatError,
    );
    expect(() => parseTpmtSignatureEcdsa(Uint8Array.from([...good, 0]))).toThrow(TpmFormatError);
  });

  it("rejects DER where a TPMT_SIGNATURE is expected", () => {
    expect(() => parseTpmtSignatureEcdsa(hex(fx.sign.derPlain))).toThrow(TpmFormatError);
  });
});
