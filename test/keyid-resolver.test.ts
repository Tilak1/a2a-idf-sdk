import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { resolveKeyid } from "../src/keyid-resolver.js";
import { p256JwkFromPoint, p256PointFromKey } from "../src/p256.js";

const RAW_PUBKEY_HEX =
  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const PEM_SPKI =
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";
const PUB_MULTIBASE = "z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";
// Computed once via the codec used by `decodeEd25519Multibase`:
// multibase prefix "z" + base58btc(multicodec 0xed 0x01 || raw_pubkey).

const hexToBytes = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

const expectedRawKey = hexToBytes(RAW_PUBKEY_HEX);

function mockFetch(body: string, contentType: string): typeof globalThis.fetch {
  return async (_url) => {
    const buf = new TextEncoder().encode(body);
    return new Response(buf, {
      status: 200,
      headers: { "content-type": contentType },
    });
  };
}

describe("keyid-resolver — dual-shape parity", () => {
  it("compact form produces the expected 32-byte raw key", async () => {
    const doc = JSON.stringify({
      address: "test@rfc8032-vec1.example",
      public_key: PEM_SPKI,
    });
    const r = await resolveKeyid("https://example.com/key", {
      fetch: mockFetch(doc, "application/json"),
    });
    expect(r.shape).toBe("compact");
    expect(r.publicKey).toEqual(expectedRawKey);
  });

  it("DID Document with publicKeyJwk produces the same 32-byte raw key", async () => {
    const x = Buffer.from(expectedRawKey)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
    const doc = JSON.stringify({
      id: "did:web:example.com",
      verificationMethod: [
        {
          id: "did:web:example.com#key-1",
          type: "JsonWebKey2020",
          controller: "did:web:example.com",
          publicKeyJwk: { kty: "OKP", crv: "Ed25519", x },
        },
      ],
      assertionMethod: ["did:web:example.com#key-1"],
    });
    const r = await resolveKeyid("https://example.com/.well-known/did.json", {
      fetch: mockFetch(doc, "application/did+json"),
    });
    expect(r.shape).toBe("did-json");
    expect(r.publicKey).toEqual(expectedRawKey);
  });

  it("rejects http(s) but non-http schemes", async () => {
    await expect(
      resolveKeyid("ftp://example.com/key", {
        fetch: mockFetch("{}", "application/json"),
      }),
    ).rejects.toThrow(/http\(s\)/);
  });

  it("rejects oversized bodies before parsing", async () => {
    const big = " ".repeat(200) + "{}"; // 202 bytes
    await expect(
      resolveKeyid("https://example.com/key", {
        fetch: mockFetch(big, "application/json"),
        maxBytes: 64,
      }),
    ).rejects.toThrow(/exceeds 64 bytes/);
  });

  it("DID Document with publicKeyMultibase produces the same raw key", async () => {
    const doc = JSON.stringify({
      id: "did:web:example.com",
      verificationMethod: [
        {
          id: "did:web:example.com#key-1",
          type: "Ed25519VerificationKey2020",
          controller: "did:web:example.com",
          publicKeyMultibase: PUB_MULTIBASE,
        },
      ],
      assertionMethod: ["did:web:example.com#key-1"],
    });
    const r = await resolveKeyid("https://example.com/.well-known/did.json", {
      fetch: mockFetch(doc, "application/did+json"),
    });
    expect(r.shape).toBe("did-json");
    expect(r.publicKey).toEqual(expectedRawKey);
  });
});

describe("keyid-resolver — EC P-256 hardware key", () => {
  const key = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey;
  const jwk = key.export({ format: "jwk" });
  const point = p256PointFromKey(key)!;
  const didDoc = (publicKeyJwk: unknown) =>
    JSON.stringify({
      id: "did:web:example.com",
      verificationMethod: [
        {
          id: "did:web:example.com#key-1",
          type: "JsonWebKey2020",
          controller: "did:web:example.com",
          publicKeyJwk,
        },
      ],
      assertionMethod: ["did:web:example.com#key-1"],
    });

  it("resolves a DID Document EC JWK to the uncompressed point", async () => {
    const r = await resolveKeyid("https://example.com/.well-known/did.json", {
      fetch: mockFetch(didDoc(jwk), "application/did+json"),
    });
    expect(r.algorithm).toBe("ecdsa-p256-sha256");
    expect(r.publicKey).toEqual(point);
    expect(r.publicKey.length).toBe(65);
    expect(p256JwkFromPoint(r.publicKey)).toEqual({ ...jwk });
  });

  it("resolves the compact form with a P-256 PEM SPKI", async () => {
    const pem = key.export({ format: "pem", type: "spki" }) as string;
    const r = await resolveKeyid("https://example.com/key", {
      fetch: mockFetch(JSON.stringify({ address: "a@b", public_key: pem }), "application/json"),
    });
    expect(r.shape).toBe("compact");
    expect(r.algorithm).toBe("ecdsa-p256-sha256");
    expect(r.publicKey).toEqual(point);
  });

  it("still reports Ed25519 documents as ed25519", async () => {
    const r = await resolveKeyid("https://example.com/key", {
      fetch: mockFetch(JSON.stringify({ address: "a@b", public_key: PEM_SPKI }), "application/json"),
    });
    expect(r.algorithm).toBe("ed25519");
  });

  it("rejects malformed or off-curve EC JWKs and other curves", async () => {
    const bad = [
      { ...jwk, y: jwk.x },
      { ...jwk, x: undefined },
      { ...jwk, crv: "P-384" },
      { ...jwk, x: "AA" },
    ];
    for (const j of bad) {
      await expect(
        resolveKeyid("https://example.com/did.json", {
          fetch: mockFetch(didDoc(j), "application/did+json"),
        }),
      ).rejects.toThrow(/EC P-256 JWK/);
    }
  });
});
