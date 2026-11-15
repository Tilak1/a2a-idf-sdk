import { describe, it, expect } from "vitest";

import {
  EvidenceFormatError,
  MAX_EVIDENCE_TEXT_BYTES,
  akMatchesPin,
  decodeEvidenceBundle,
  encodeEvidenceBundle,
  type TpmEvidenceBundle,
} from "../../src/tpm/evidence.js";
import { fx, hex, realEvidence } from "./helpers.js";
import { createPublicKey } from "node:crypto";

const akSpki = (pem: string): Uint8Array =>
  new Uint8Array(
    createPublicKey(pem).export({ format: "der", type: "spki" }),
  );

const bundle: TpmEvidenceBundle = {
  ...realEvidence,
  akPublic: akSpki(fx.akPem),
};

describe("evidence bundle encoding", () => {
  it("round-trips the captured vTPM evidence", () => {
    const decoded = decodeEvidenceBundle(encodeEvidenceBundle(bundle));
    expect(decoded).toEqual(bundle);
    expect(Buffer.from(decoded.certInfo).toString("hex")).toBe(fx.certInfo);
  });

  it("uses unpadded base64url", () => {
    const text = encodeEvidenceBundle(bundle);
    expect(text).not.toMatch(/[+/=]/);
    expect(JSON.parse(text).v).toBe(1);
  });

  const good = JSON.parse(encodeEvidenceBundle(bundle));
  const bad: [string, unknown][] = [
    ["a wrong version", { ...good, v: 2 }],
    ["a missing field", { ...good, akPublic: undefined }],
    ["an unknown field", { ...good, extra: "AA" }],
    ["standard base64", { ...good, certInfo: Buffer.from(hex(fx.certInfo)).toString("base64") }],
    ["non-canonical trailing bits", { ...good, certSignature: "AB" }],
    ["an empty field", { ...good, certSignature: "" }],
    ["an oversized field", { ...good, certInfo: "A".repeat(6000) }],
    ["a non-string field", { ...good, certInfo: 5 }],
    ["an array", [good]],
    ["null", null],
  ];
  it.each(bad)("rejects %s", (_name, value) => {
    expect(() => decodeEvidenceBundle(JSON.stringify(value))).toThrow(EvidenceFormatError);
  });

  it("rejects non-JSON and oversized input", () => {
    expect(() => decodeEvidenceBundle("{nope")).toThrow(EvidenceFormatError);
    expect(() => decodeEvidenceBundle(" ".repeat(MAX_EVIDENCE_TEXT_BYTES + 1))).toThrow(
      EvidenceFormatError,
    );
  });
});

describe("akMatchesPin", () => {
  it("matches the pinned AK as PEM or KeyObject", () => {
    expect(akMatchesPin(bundle.akPublic, fx.akPem)).toBe(true);
    expect(akMatchesPin(bundle.akPublic, createPublicKey(fx.akPem))).toBe(true);
  });

  it("does not match a different key, or garbage", () => {
    expect(akMatchesPin(bundle.akPublic, fx.keyPem)).toBe(false);
    expect(akMatchesPin(new Uint8Array([1, 2, 3]), fx.akPem)).toBe(false);
    expect(akMatchesPin(bundle.akPublic, "not a pem")).toBe(false);
  });
});
