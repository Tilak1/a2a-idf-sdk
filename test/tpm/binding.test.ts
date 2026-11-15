import { readFileSync } from "node:fs";
import {
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";
import { describe, it, expect } from "vitest";

import {
  verifyTpmBinding,
  type EcP256Jwk,
  type TpmEvidence,
} from "../../src/tpm/binding.js";
import {
  TPM_ALG_ECDSA,
  TPM_ALG_SHA256,
  TPM_GENERATED_VALUE,
  TPM_ST_ATTEST_CERTIFY,
  computeTpmName,
  parseTpm2bPublic,
} from "../../src/tpm/structures.js";

const fx = JSON.parse(
  readFileSync(new URL("./fixtures/vtpm-p256.json", import.meta.url), "utf8"),
);
const hex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, "hex"));
const jwkOf = (pem: string): EcP256Jwk =>
  createPublicKey(pem).export({ format: "jwk" }) as EcP256Jwk;

const nonce = hex(fx.nonce);
const keyJwk = jwkOf(fx.keyPem);
const realEvidence: TpmEvidence = {
  certInfo: hex(fx.certInfo),
  certSignature: hex(fx.certSigTss),
  keyPublic: hex(fx.keyPub),
};

const verifyReal = (over: Partial<Parameters<typeof verifyTpmBinding>[0]> = {}) =>
  verifyTpmBinding({
    evidence: realEvidence,
    akPublicKey: fx.akPem,
    expectedNonce: nonce,
    jwk: keyJwk,
    ...over,
  });

// --- helpers to build AK-signed evidence with chosen contents -------------

const u16 = (n: number): number[] => [(n >> 8) & 0xff, n & 0xff];
const u32 = (n: number): number[] => [...u16(n >>> 16), ...u16(n & 0xffff)];
const tpm2b = (b: Uint8Array): number[] => [...u16(b.length), ...b];

function buildAttest(extraData: Uint8Array, certifiedName: Uint8Array): Uint8Array {
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

function tpmtSignature(raw: Uint8Array, hashAlg = TPM_ALG_SHA256): Uint8Array {
  return Uint8Array.from([
    ...u16(TPM_ALG_ECDSA),
    ...u16(hashAlg),
    ...tpm2b(raw.subarray(0, 32)),
    ...tpm2b(raw.subarray(32)),
  ]);
}

interface Synthetic {
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

function syntheticAk(): Synthetic {
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
const editKeyPublic = (edit: (b: Uint8Array) => void): Uint8Array => {
  const b = Uint8Array.from(realEvidence.keyPublic);
  edit(b);
  return b;
};
// TPM2B_PUBLIC layout: size(2) type(2) nameAlg(2) objectAttributes(4) ...
const ATTR_LOW_BYTE = 9;
const CURVE_LOW_BYTE = 19;

describe("verifyTpmBinding", () => {
  it("accepts the captured vTPM evidence for the issued nonce and JWK", () => {
    const r = verifyReal();
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(Buffer.from(r.attest.extraData).toString("hex")).toBe(fx.nonce);
      expect(Buffer.from(r.key.x).toString("base64url")).toBe(keyJwk.x);
    }
  });

  it("rejects a different nonce (replayed evidence against a new challenge)", () => {
    const fresh = Uint8Array.from(nonce);
    fresh[0] ^= 1;
    expect(verifyReal({ expectedNonce: fresh })).toEqual({
      ok: false,
      reason: "nonce-mismatch",
    });
  });

  it("rejects the stock tpm2_certify extraData that ignores the nonce", () => {
    const ak = syntheticAk();
    const ev = ak.make({ extraData: hex("00ff55aa") });
    const r = verifyTpmBinding({
      evidence: ev,
      akPublicKey: ak.akPem,
      expectedNonce: nonce,
      jwk: keyJwk,
    });
    expect(r).toEqual({ ok: false, reason: "nonce-mismatch" });
  });

  it("rejects a tampered Certify structure", () => {
    const certInfo = Uint8Array.from(realEvidence.certInfo);
    certInfo[certInfo.length - 1] ^= 1;
    expect(verifyReal({ evidence: { ...realEvidence, certInfo } })).toEqual({
      ok: false,
      reason: "ak-signature-invalid",
    });
  });

  it("rejects evidence signed by a different AK than the pinned one", () => {
    expect(verifyReal({ akPublicKey: fx.keyPem })).toEqual({
      ok: false,
      reason: "ak-signature-invalid",
    });
    const other = syntheticAk();
    expect(verifyReal({ akPublicKey: other.akPem })).toEqual({
      ok: false,
      reason: "ak-signature-invalid",
    });
  });

  it("rejects a certify whose name is for a different key", () => {
    const ak = syntheticAk();
    const ev = ak.make({ certifiedName: hex("000b" + "00".repeat(32)) });
    expect(
      verifyTpmBinding({
        evidence: ev,
        akPublicKey: ak.akPem,
        expectedNonce: nonce,
        jwk: keyJwk,
      }),
    ).toEqual({ ok: false, reason: "name-mismatch" });
  });

  it("rejects a key public area swapped after certification", () => {
    const swapped = editKeyPublic((b) => {
      b[b.length - 1] ^= 1; // y differs, so the recomputed name differs
    });
    expect(
      verifyReal({ evidence: { ...realEvidence, keyPublic: swapped } }),
    ).toEqual({ ok: false, reason: "name-mismatch" });
  });

  it.each([
    ["fixedTPM", 1 << 1],
    ["fixedParent", 1 << 4],
    ["sensitiveDataOrigin", 1 << 5],
    ["sign", 1 << 2], // bit 18 lives in the second attribute byte (0x04)
  ])("rejects a certified key lacking %s", (name, bit) => {
    const ak = syntheticAk();
    const keyPublic = editKeyPublic((b) => {
      if (name === "sign") b[ATTR_LOW_BYTE - 2]! &= ~bit;
      else b[ATTR_LOW_BYTE]! &= ~bit;
    });
    expect(
      verifyTpmBinding({
        evidence: ak.make({ keyPublic }),
        akPublicKey: ak.akPem,
        expectedNonce: nonce,
        jwk: keyJwk,
      }),
    ).toEqual({ ok: false, reason: "key-not-hardware-bound" });
  });

  it("rejects a certified key on a curve other than P-256", () => {
    const ak = syntheticAk();
    const keyPublic = editKeyPublic((b) => {
      b[CURVE_LOW_BYTE] = 0x04; // TPM_ECC_NIST_P384
    });
    expect(
      verifyTpmBinding({
        evidence: ak.make({ keyPublic }),
        akPublicKey: ak.akPem,
        expectedNonce: nonce,
        jwk: keyJwk,
      }),
    ).toEqual({ ok: false, reason: "unsupported-key-curve" });
  });

  it("rejects a JWK that is not the certified key", () => {
    expect(verifyReal({ jwk: jwkOf(fx.akPem) })).toEqual({
      ok: false,
      reason: "jwk-mismatch",
    });
    expect(verifyReal({ jwk: { ...keyJwk, y: jwkOf(fx.akPem).y } })).toEqual({
      ok: false,
      reason: "jwk-mismatch",
    });
  });

  it("rejects malformed or wrong-type JWKs", () => {
    const cases: EcP256Jwk[] = [
      { ...keyJwk, crv: "P-384" },
      { ...keyJwk, kty: "OKP" },
      { ...keyJwk, x: undefined },
      { ...keyJwk, x: keyJwk.x + "A" },
      { ...keyJwk, y: "!".repeat(43) },
      { ...keyJwk, x: Buffer.from(keyJwk.x!, "base64url").toString("base64") },
    ];
    for (const jwk of cases) {
      expect(verifyReal({ jwk }), JSON.stringify(jwk)).toEqual({
        ok: false,
        reason: "jwk-malformed",
      });
    }
  });

  it("reports malformed evidence instead of throwing", () => {
    const bad: Partial<TpmEvidence>[] = [
      { keyPublic: realEvidence.keyPublic.subarray(0, 20) },
      { certSignature: realEvidence.certSignature.subarray(0, 10) },
      { certSignature: new Uint8Array(0) },
    ];
    for (const part of bad) {
      expect(verifyReal({ evidence: { ...realEvidence, ...part } })).toEqual({
        ok: false,
        reason: "malformed-evidence",
      });
    }
  });

  it("reports a validly signed but non-certify structure as malformed", () => {
    const ak = syntheticAk();
    const certInfo = Uint8Array.from(realEvidence.certInfo);
    certInfo[5] = 0x18; // TPM_ST_ATTEST_QUOTE
    expect(
      verifyTpmBinding({
        evidence: ak.signCertInfo(certInfo),
        akPublicKey: ak.akPem,
        expectedNonce: nonce,
        jwk: keyJwk,
      }),
    ).toEqual({ ok: false, reason: "malformed-evidence" });
  });

  it("rejects an AK signature that is not SHA-256", () => {
    const sig = Uint8Array.from(realEvidence.certSignature);
    sig[3] = 0x0c; // TPM_ALG_SHA384
    expect(verifyReal({ evidence: { ...realEvidence, certSignature: sig } })).toEqual({
      ok: false,
      reason: "unsupported-signature-algorithm",
    });
  });

  it("throws on caller misconfiguration instead of failing the evidence", () => {
    expect(() => verifyReal({ expectedNonce: new Uint8Array(0) })).toThrow(/expectedNonce/);
    const ed = generateKeyPairSync("ed25519").publicKey;
    expect(() => verifyReal({ akPublicKey: ed })).toThrow(/P-256/);
    const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" }).publicKey;
    expect(() => verifyReal({ akPublicKey: p384 })).toThrow(/P-256/);
  });
});
