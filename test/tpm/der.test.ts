import { readFileSync } from "node:fs";
import { verify as cryptoVerify } from "node:crypto";
import { sha256 } from "@noble/hashes/sha256";
import { describe, it, expect } from "vitest";

import {
  derToRaw,
  rawToDer,
  rsToRaw,
  EcdsaEncodingError,
} from "../../src/tpm/der.js";

const fx = JSON.parse(
  readFileSync(new URL("./fixtures/vtpm-p256.json", import.meta.url), "utf8"),
);
const hex = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, "hex"));
const message = new TextEncoder().encode("GET /x");

const verifiesRaw = (raw: Uint8Array): boolean =>
  cryptoVerify(
    "sha256",
    message,
    { key: fx.keyPem, dsaEncoding: "ieee-p1363" },
    raw,
  );

describe("derToRaw", () => {
  it("converts the 71-byte DER signature captured from tpm2_sign -f plain", () => {
    const der = hex(fx.sign.derPlain);
    expect(der.length).toBe(71); // r has a 0x00 pad byte
    const raw = derToRaw(der);
    expect(raw.length).toBe(64);
    expect(verifiesRaw(raw)).toBe(true);
  });

  it("is what makes a DER signature verify as ecdsa-p256-sha256", () => {
    // Fed to a verifier that expects raw r||s, DER must not verify.
    expect(verifiesRaw(hex(fx.sign.derPlain))).toBe(false);
  });

  it("left-pads integers shorter than 32 bytes", () => {
    // r = 0x01, s = 0x80..00 (needs a pad byte in DER)
    const s = new Uint8Array(32);
    s[0] = 0x80;
    const der = Uint8Array.from([
      0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00, ...s,
    ]);
    const raw = derToRaw(der);
    expect(raw[31]).toBe(0x01);
    expect(raw.subarray(0, 31).every((b) => b === 0)).toBe(true);
    expect(raw.subarray(32)).toEqual(s);
  });

  it("round-trips r||s through DER for varied leading zeros and top bits", () => {
    for (let i = 0; i < 300; i++) {
      const raw = new Uint8Array([
        ...sha256(Uint8Array.of(i, 1)),
        ...sha256(Uint8Array.of(i, 2)),
      ]);
      if (i % 3 === 0) raw[0] = 0; // r with a leading zero byte
      if (i % 5 === 0) raw.fill(0, 32, 34); // s with two leading zero bytes
      if (i % 7 === 0) raw[32] |= 0x80; // s with the top bit set
      expect(derToRaw(rawToDer(raw))).toEqual(raw);
    }
  });

  it("rejects a raw 64-byte signature passed as DER", () => {
    const raw = derToRaw(hex(fx.sign.derPlain));
    expect(() => derToRaw(raw)).toThrow(EcdsaEncodingError);
  });

  it("rejects malformed DER", () => {
    const good = hex(fx.sign.derPlain);
    const bad: Array<[string, Uint8Array, RegExp]> = [
      ["empty", new Uint8Array(0), /truncated/],
      ["truncated", good.subarray(0, good.length - 1), /length mismatch/],
      ["trailing", Uint8Array.from([...good, 0]), /length mismatch/],
      ["wrong outer tag", Uint8Array.from([0x31, ...good.subarray(1)]), /not a SEQUENCE/],
      [
        "wrong integer tag",
        Uint8Array.from([...good.subarray(0, 2), 0x03, ...good.subarray(3)]),
        /not an INTEGER/,
      ],
      ["negative r", Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01]), /negative/],
      [
        "non-minimal r pad",
        Uint8Array.from([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01]),
        /non-minimal encoding/,
      ],
      ["empty integer", Uint8Array.from([0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01]), /invalid length/],
      [
        "r wider than 32 bytes",
        Uint8Array.from([0x30, 0x26, 0x02, 0x21, 0x01, ...new Uint8Array(32), 0x02, 0x01, 0x01]),
        /at most 32/,
      ],
    ];
    for (const [name, der, reason] of bad) {
      expect(() => derToRaw(der), name).toThrow(reason);
    }
  });
});

describe("rsToRaw / rawToDer", () => {
  it("pads and rejects oversized values", () => {
    expect(rsToRaw(Uint8Array.of(1), Uint8Array.of(2)).length).toBe(64);
    expect(() => rsToRaw(Uint8Array.of(1, ...new Uint8Array(32)), Uint8Array.of(2))).toThrow(
      EcdsaEncodingError,
    );
  });

  it("rawToDer matches the DER the TPM emitted for the same r||s", () => {
    const der = hex(fx.sign.derPlain);
    expect(rawToDer(derToRaw(der))).toEqual(der);
  });

  it("rawToDer rejects the wrong length", () => {
    expect(() => rawToDer(new Uint8Array(63))).toThrow(EcdsaEncodingError);
  });
});
