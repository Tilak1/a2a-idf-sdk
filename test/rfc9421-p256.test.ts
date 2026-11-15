import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";

import {
  parseP256SignatureInput,
  signEcdsaP256,
  verifyEcdsaP256,
  type P256Signer,
  type SignP256Inputs,
  type VerifyP256Inputs,
} from "../src/rfc9421-p256.js";
import { ReplayCache } from "../src/replay-cache.js";
import { p256PointFromKey } from "../src/p256.js";
import { derToRaw } from "../src/tpm/der.js";
import { sign as signEd25519 } from "../src/rfc9421.js";

const kp = generateKeyPairSync("ec", { namedCurve: "P-256" });
const point = p256PointFromKey(kp.publicKey)!;
const rawSigner: P256Signer = (m) =>
  cryptoSign("sha256", m, { key: kp.privateKey, dsaEncoding: "ieee-p1363" });

const NOW = 1_800_000_000;
const body = new TextEncoder().encode('{"hello":"world"}');
const base: SignP256Inputs = {
  method: "post",
  authority: "Agent.Example.com",
  path: "/a2a/message?x=1",
  body,
  params: {
    keyid: "https://agent.example.com/.well-known/did.json",
    created: NOW,
    expires: NOW + 120,
    nonce: "chal-0123456789abcdef",
  },
};

const headersOf = (h: Awaited<ReturnType<typeof signEcdsaP256>>) => ({
  "content-digest": h["Content-Digest"],
  "signature-input": h["Signature-Input"],
  signature: h.Signature,
});

async function signedRequest(over: Partial<SignP256Inputs> = {}) {
  const h = await signEcdsaP256({ ...base, ...over }, rawSigner);
  const verifyInputs: VerifyP256Inputs = {
    method: "POST",
    authority: "agent.example.com",
    path: base.path,
    body,
    headers: headersOf(h),
    publicKey: point,
    nowSeconds: NOW + 5,
  };
  return { h, verifyInputs };
}

describe("ecdsa-p256-sha256 request signatures", () => {
  it("signs and verifies, emitting the alg and component set", async () => {
    const { h, verifyInputs } = await signedRequest();
    expect(h["Signature-Input"]).toBe(
      'sig1=("@method" "@authority" "@path" "content-digest");created=1800000000;expires=1800000120;' +
        'keyid="https://agent.example.com/.well-known/did.json";alg="ecdsa-p256-sha256";nonce="chal-0123456789abcdef"',
    );
    const r = verifyEcdsaP256(verifyInputs);
    expect(r).toEqual({ ok: true, params: base.params });
  });

  it("emits a 64-byte raw r||s signature", async () => {
    const { h } = await signedRequest();
    const b64 = h.Signature.slice("sig1=:".length, -1);
    expect(Buffer.from(b64, "base64").length).toBe(64);
  });

  it("accepts a signer that converts DER to raw (the TPM path)", async () => {
    const derSigner: P256Signer = (m) =>
      derToRaw(cryptoSign("sha256", m, { key: kp.privateKey, dsaEncoding: "der" }));
    const h = await signEcdsaP256(base, derSigner);
    const r = verifyEcdsaP256({
      method: "POST", authority: "agent.example.com", path: base.path, body,
      headers: headersOf(h), publicKey: point, nowSeconds: NOW,
    });
    expect(r.ok).toBe(true);
  });

  it("refuses a signer that returns DER instead of raw r||s", async () => {
    const der: P256Signer = (m) =>
      cryptoSign("sha256", m, { key: kp.privateKey, dsaEncoding: "der" });
    await expect(signEcdsaP256(base, der)).rejects.toThrow(/raw r\|\|s/);
  });

  it("rejects a signature by a different key", async () => {
    const other = p256PointFromKey(generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey)!;
    const { verifyInputs } = await signedRequest();
    expect(verifyEcdsaP256({ ...verifyInputs, publicKey: other })).toEqual({
      ok: false, reason: "signature-invalid",
    });
  });

  it("rejects each tampered request component", async () => {
    const { verifyInputs } = await signedRequest();
    const cases: Partial<VerifyP256Inputs>[] = [
      { method: "PUT" },
      { authority: "evil.example.com" },
      { path: "/a2a/other" },
    ];
    for (const c of cases) {
      expect(verifyEcdsaP256({ ...verifyInputs, ...c }), JSON.stringify(c)).toEqual({
        ok: false, reason: "signature-invalid",
      });
    }
    expect(
      verifyEcdsaP256({ ...verifyInputs, body: new TextEncoder().encode("{}") }),
    ).toEqual({ ok: false, reason: "content-digest-mismatch" });
  });

  it("treats authority case-insensitively", async () => {
    const { verifyInputs } = await signedRequest();
    expect(verifyEcdsaP256({ ...verifyInputs, authority: "AGENT.example.com" }).ok).toBe(true);
  });

  it("rejects tampered signature bytes and wrong-length signatures", async () => {
    const { h, verifyInputs } = await signedRequest();
    const raw = Buffer.from(h.Signature.slice(6, -1), "base64");
    raw[10]! ^= 1;
    const flipped = { ...verifyInputs.headers, signature: `sig1=:${raw.toString("base64")}:` };
    expect(verifyEcdsaP256({ ...verifyInputs, headers: flipped })).toEqual({
      ok: false, reason: "signature-invalid",
    });
    const short = { ...verifyInputs.headers, signature: `sig1=:${raw.subarray(0, 63).toString("base64")}:` };
    expect(verifyEcdsaP256({ ...verifyInputs, headers: short })).toEqual({
      ok: false, reason: "malformed-signature",
    });
  });

  it("enforces created, skew and expires", async () => {
    const { verifyInputs } = await signedRequest();
    expect(verifyEcdsaP256({ ...verifyInputs, nowSeconds: NOW + 120 })).toEqual({
      ok: false, reason: "signature-expired",
    });
    expect(verifyEcdsaP256({ ...verifyInputs, nowSeconds: NOW + 119 }).ok).toBe(true);
    expect(verifyEcdsaP256({ ...verifyInputs, nowSeconds: NOW - 31 })).toEqual({
      ok: false, reason: "timestamp-future-skew",
    });
    const long = await signedRequest({ params: { ...base.params, expires: NOW + 10_000 } });
    expect(verifyEcdsaP256({ ...long.verifyInputs, nowSeconds: NOW + 301 })).toEqual({
      ok: false, reason: "timestamp-too-old",
    });
  });

  it("binds the signed nonce to the challenge when expectedNonce is set", async () => {
    const { verifyInputs } = await signedRequest();
    expect(verifyEcdsaP256({ ...verifyInputs, expectedNonce: base.params.nonce }).ok).toBe(true);
    expect(verifyEcdsaP256({ ...verifyInputs, expectedNonce: "other" })).toEqual({
      ok: false, reason: "nonce-mismatch",
    });
  });

  it("detects replays only after the signature verifies", async () => {
    const cache = new ReplayCache();
    const { verifyInputs } = await signedRequest();
    const v = { ...verifyInputs, checkNonce: cache.check.bind(cache) };
    expect(verifyEcdsaP256(v).ok).toBe(true);
    expect(verifyEcdsaP256(v)).toEqual({ ok: false, reason: "replay-detected" });

    const cache2 = new ReplayCache();
    const forged = { ...verifyInputs, path: "/x", checkNonce: cache2.check.bind(cache2) };
    expect(verifyEcdsaP256(forged).ok).toBe(false);
    expect(cache2.size()).toBe(0); // a forged request cannot burn the nonce
  });

  it("is not satisfied by an Ed25519-profile signature", () => {
    const h = signEd25519({
      method: "POST", path: base.path, body,
      params: { keyid: base.params.keyid, created: NOW, nonce: base.params.nonce },
      privateKey: new Uint8Array(32).fill(1),
    });
    const r = verifyEcdsaP256({
      method: "POST", authority: "agent.example.com", path: base.path, body,
      headers: headersOf(h), publicKey: point, nowSeconds: NOW,
    });
    expect(r).toEqual({ ok: false, reason: "malformed-signature-input" });
  });

  it("reports a different alg as algorithm-mismatch", async () => {
    const { verifyInputs } = await signedRequest();
    const swapped = verifyInputs.headers["signature-input"]!.replace(
      "ecdsa-p256-sha256", "ed25519",
    );
    expect(
      verifyEcdsaP256({ ...verifyInputs, headers: { ...verifyInputs.headers, "signature-input": swapped } }),
    ).toEqual({ ok: false, reason: "algorithm-mismatch" });
  });

  it("rejects missing headers, an invalid key and a missing digest", async () => {
    const { verifyInputs } = await signedRequest();
    expect(verifyEcdsaP256({ ...verifyInputs, headers: {} })).toEqual({
      ok: false, reason: "missing-headers",
    });
    expect(verifyEcdsaP256({ ...verifyInputs, publicKey: new Uint8Array(32) })).toEqual({
      ok: false, reason: "invalid-public-key",
    });
    const bad = Uint8Array.from(point);
    bad[40]! ^= 1; // off the curve
    expect(verifyEcdsaP256({ ...verifyInputs, publicKey: bad })).toEqual({
      ok: false, reason: "invalid-public-key",
    });
    const { "content-digest": _d, ...rest } = verifyInputs.headers;
    expect(verifyEcdsaP256({ ...verifyInputs, headers: rest })).toEqual({
      ok: false, reason: "content-digest-missing",
    });
  });
});

describe("parseP256SignatureInput", () => {
  it("round-trips and exposes the keyid before verification", async () => {
    const { h } = await signedRequest({ params: { ...base.params, tag: "a2a-message" } });
    expect(parseP256SignatureInput(h["Signature-Input"])?.keyid).toBe(base.params.keyid);
    expect(parseP256SignatureInput(h["Signature-Input"])?.tag).toBe("a2a-message");
  });

  it("rejects reordered, reduced or extended inputs", async () => {
    const { h } = await signedRequest();
    const v = h["Signature-Input"];
    const bad = [
      v.replace('"@authority" ', ""),
      v.replace('"@method" "@authority"', '"@authority" "@method"'),
      v.replace(";nonce=", ";x=1;nonce="),
      v.replace("created=1800000000;expires=1800000120", "expires=1800000120;created=1800000000"),
      v.replace("expires=1800000120", "expires=1799999999"),
      v + ";tag=\"a\";tag=\"b\"",
    ];
    for (const b of bad) expect(parseP256SignatureInput(b), b).toBeNull();
  });
});

describe("signEcdsaP256 input validation", () => {
  it.each([
    ["a quote in the nonce", { params: { ...base.params, nonce: 'a"b' } }],
    ["a backslash in the keyid", { params: { ...base.params, keyid: "a\\b" } }],
    ["a newline in the path", { path: "/a\nb" }],
    ["an empty authority", { authority: "" }],
    ["an authority with a slash", { authority: "a/b" }],
    ["expires not after created", { params: { ...base.params, expires: NOW } }],
  ] as [string, Partial<SignP256Inputs>][])("rejects %s", async (_n, over) => {
    await expect(signEcdsaP256({ ...base, ...over }, rawSigner)).rejects.toThrow(TypeError);
  });
});
