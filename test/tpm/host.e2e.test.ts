// End-to-end run against a real TPM (e.g. the Hyper-V vTPM). Skipped unless
// /dev/tpmrm0 is accessible and tpm2-tools is installed. Uses its own
// persistent handles, so it does not disturb other keys on the TPM.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createPublicKey } from "node:crypto";

import { NonceChallenger } from "../../src/tpm/challenge.js";
import { encodeEvidenceBundle } from "../../src/tpm/evidence.js";
import { TpmHost, type HardwareKeyInfo } from "../../src/tpm/host.js";
import { verifyHardwareBoundRequest, type HardwareBoundRequest } from "../../src/tpm/policy.js";
import { signEcdsaP256, verifyEcdsaP256 } from "../../src/rfc9421-p256.js";
import { p256PointFromJwk } from "../../src/p256.js";
import { tpmAvailable } from "./helpers.js";

const KEYID = "https://agent.example.com/.well-known/did.json";
const BODY = new TextEncoder().encode('{"task":"run"}');
const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");

describe.skipIf(!tpmAvailable())("real TPM host (vTPM end to end)", () => {
  const host = new TpmHost({ akHandle: 0x81010020, keyHandle: 0x81010021 });
  let info: HardwareKeyInfo;

  beforeAll(async () => {
    info = await host.provision({ replace: true });
  }, 120_000);

  afterAll(async () => {
    await host.release();
  }, 60_000);

  const didFetch = (jwk: unknown): typeof globalThis.fetch => async () =>
    new Response(
      JSON.stringify({
        id: "did:web:agent.example.com",
        verificationMethod: [
          { id: "did:web:agent.example.com#k", type: "JsonWebKey2020",
            controller: "did:web:agent.example.com", publicKeyJwk: jwk },
        ],
        assertionMethod: ["did:web:agent.example.com#k"],
      }),
      { status: 200, headers: { "content-type": "application/did+json" } },
    );

  async function request(
    nonce: Uint8Array,
    evidence: string | undefined,
  ): Promise<HardwareBoundRequest> {
    const now = Math.floor(Date.now() / 1000);
    const h = await signEcdsaP256(
      { method: "POST", authority: "agent.example.com", path: "/a2a", body: BODY,
        params: { keyid: KEYID, created: now, expires: now + 60, nonce: b64u(nonce) } },
      host.signer,
    );
    return {
      method: "POST", authority: "agent.example.com", path: "/a2a", body: BODY,
      headers: {
        "content-digest": h["Content-Digest"],
        "signature-input": h["Signature-Input"],
        signature: h.Signature,
      },
      ...(evidence !== undefined ? { evidence } : {}),
    };
  }

  const verify = (req: HardwareBoundRequest, challenger: NonceChallenger) =>
    verifyHardwareBoundRequest({
      request: req,
      challenger,
      pinnedAk: info.akPem,
      resolve: { fetch: didFetch(info.jwk) },
    });

  it("provisions fixed P-256 keys and exports a valid JWK", () => {
    expect(info.jwk.crv).toBe("P-256");
    expect(p256PointFromJwk(info.jwk)).toBeDefined();
    expect(createPublicKey(info.akPem).asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
  });

  it("signs with the TPM key: raw r||s verifies against the published JWK", async () => {
    const now = Math.floor(Date.now() / 1000);
    const nonce = new Uint8Array(32).fill(1);
    const h = await signEcdsaP256(
      { method: "GET", authority: "agent.example.com", path: "/x", body: new Uint8Array(0),
        params: { keyid: KEYID, created: now, expires: now + 60, nonce: b64u(nonce) } },
      host.signer,
    );
    const r = verifyEcdsaP256({
      method: "GET", authority: "agent.example.com", path: "/x", body: new Uint8Array(0),
      headers: { "content-digest": h["Content-Digest"], "signature-input": h["Signature-Input"], signature: h.Signature },
      publicKey: p256PointFromJwk(info.jwk)!,
    });
    expect(r.ok).toBe(true);
  });

  it("run 1: hardware key and fresh nonce passes", async () => {
    const challenger = new NonceChallenger();
    const nonce = challenger.issue();
    const evidence = encodeEvidenceBundle(await host.certify(nonce));
    const r = await verify(await request(nonce, evidence), challenger);
    expect(r.ok).toBe(true);
  }, 60_000);

  it("run 2a: the same signed request without evidence fails", async () => {
    const challenger = new NonceChallenger();
    const nonce = challenger.issue();
    expect(await verify(await request(nonce, undefined), challenger)).toEqual({
      ok: false, reason: "evidence-missing",
    });
  });

  it("run 3: evidence from an old challenge replayed against a new one fails", async () => {
    const challenger = new NonceChallenger();
    const old = challenger.issue();
    const oldEvidence = encodeEvidenceBundle(await host.certify(old));
    const fresh = challenger.issue();
    expect(await verify(await request(fresh, oldEvidence), challenger)).toEqual({
      ok: false, reason: "nonce-mismatch",
    });
    expect(challenger.has(fresh)).toBe(true);
  }, 60_000);

  it("rejects the evidence under a different pinned AK", async () => {
    const challenger = new NonceChallenger();
    const nonce = challenger.issue();
    const evidence = encodeEvidenceBundle(await host.certify(nonce));
    const r = await verifyHardwareBoundRequest({
      request: await request(nonce, evidence),
      challenger,
      // An unrelated P-256 key, standing in for an AK the relying party did not pin.
      pinnedAk: createPublicKey(
        "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5XXoIJU1hvOfhraZ4hYVMnG/ZNTX\nUeJskffO4uZOIveQeYhVjOhQTfebwzFWOzuHBWmxuTw6jFMHspJMtr0Ukg==\n-----END PUBLIC KEY-----\n",
      ),
      resolve: { fetch: didFetch(info.jwk) },
    });
    expect(r).toEqual({ ok: false, reason: "ak-not-pinned" });
  }, 60_000);
});
