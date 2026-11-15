import { describe, it, expect } from "vitest";
import { createPublicKey, generateKeyPairSync, sign as cryptoSign } from "node:crypto";

import { NonceChallenger } from "../../src/tpm/challenge.js";
import { encodeEvidenceBundle } from "../../src/tpm/evidence.js";
import {
  verifyHardwareBoundRequest,
  type EvidenceAppraiser,
  type HardwareBoundRequest,
} from "../../src/tpm/policy.js";
import { signEcdsaP256 } from "../../src/rfc9421-p256.js";
import { sign as signEd25519 } from "../../src/rfc9421.js";
import { p256PointFromKey } from "../../src/p256.js";
import { keyPublicForPoint, syntheticAk } from "./helpers.js";

const NOW = 1_800_000_000;
const KEYID = "https://agent.example.com/.well-known/did.json";
const BODY = new TextEncoder().encode('{"task":"run"}');

const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");
const newKey = () => {
  const kp = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...kp, point: p256PointFromKey(kp.publicKey)! };
};

const didDoc = (publicKeyJwk: unknown): string =>
  JSON.stringify({
    id: "did:web:agent.example.com",
    verificationMethod: [
      {
        id: "did:web:agent.example.com#k",
        type: "JsonWebKey2020",
        controller: "did:web:agent.example.com",
        publicKeyJwk,
      },
    ],
    assertionMethod: ["did:web:agent.example.com#k"],
  });

function world() {
  const ak = syntheticAk();
  const hw = newKey(); // stands in for the TPM-resident signing key
  const clock = { t: NOW };
  const challenger = new NonceChallenger({ ttlSeconds: 60, now: () => clock.t });
  let published: string = didDoc(hw.publicKey.export({ format: "jwk" }));
  let contentType = "application/did+json";
  let fetches = 0;
  const fetch: typeof globalThis.fetch = async () => {
    fetches++;
    return new Response(published, {
      status: 200,
      headers: { "content-type": contentType },
    });
  };

  const evidenceFor = (nonce: Uint8Array, point = hw.point): string => {
    const keyPublic = keyPublicForPoint(point);
    const ev = ak.make({ keyPublic, extraData: nonce });
    return encodeEvidenceBundle({
      ...ev,
      akPublic: new Uint8Array(
        createPublicKey(ak.akPem).export({ format: "der", type: "spki" }),
      ),
    });
  };

  const request = async (
    nonce: Uint8Array,
    opts: { signer?: typeof hw; evidence?: string | null } = {},
  ): Promise<HardwareBoundRequest> => {
    const signer = opts.signer ?? hw;
    const h = await signEcdsaP256(
      {
        method: "POST",
        authority: "agent.example.com",
        path: "/a2a",
        body: BODY,
        params: { keyid: KEYID, created: NOW, expires: NOW + 60, nonce: b64u(nonce) },
      },
      (m) => cryptoSign("sha256", m, { key: signer.privateKey, dsaEncoding: "ieee-p1363" }),
    );
    const evidence = opts.evidence === undefined ? evidenceFor(nonce) : opts.evidence;
    return {
      method: "POST",
      authority: "agent.example.com",
      path: "/a2a",
      body: BODY,
      headers: {
        "content-digest": h["Content-Digest"],
        "signature-input": h["Signature-Input"],
        signature: h.Signature,
      },
      ...(evidence !== null ? { evidence } : {}),
    };
  };

  const verify = (
    req: HardwareBoundRequest,
    pinned: Parameters<typeof verifyHardwareBoundRequest>[0]["pinnedAk"] = ak.akPem,
    appraiser?: EvidenceAppraiser,
  ) =>
    verifyHardwareBoundRequest({
      request: req,
      challenger,
      pinnedAk: pinned,
      ...(appraiser ? { appraiser } : {}),
      resolve: { fetch },
      nowSeconds: NOW + 1,
    });

  return {
    ak, hw, clock, challenger, request, verify, evidenceFor,
    publish: (doc: string, type = "application/did+json") => {
      published = doc;
      contentType = type;
    },
    fetches: () => fetches,
  };
}

describe("verifyHardwareBoundRequest: the three demo runs", () => {
  it("run 1: hardware-bound key with a fresh nonce passes", async () => {
    const w = world();
    const n = w.challenger.issue();
    const r = await w.verify(await w.request(n));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.keyid).toBe(KEYID);
      expect(r.params.nonce).toBe(b64u(n));
    }
    expect(w.challenger.has(n)).toBe(false); // consumed
  });

  it("run 2a: a request with no hardware evidence fails", async () => {
    const w = world();
    const n = w.challenger.issue();
    expect(await w.verify(await w.request(n, { evidence: null }))).toEqual({
      ok: false, reason: "evidence-missing",
    });
    expect(w.challenger.has(n)).toBe(true);
  });

  it("run 2a: a software Ed25519 key fails", async () => {
    const w = world();
    const n = w.challenger.issue();
    const ed = signEd25519({
      method: "POST", path: "/a2a", body: BODY,
      params: { keyid: KEYID, created: NOW, nonce: b64u(n) },
      privateKey: new Uint8Array(32).fill(3),
    });
    const req: HardwareBoundRequest = {
      method: "POST", authority: "agent.example.com", path: "/a2a", body: BODY,
      headers: {
        "content-digest": ed["Content-Digest"],
        "signature-input": ed["Signature-Input"],
        signature: ed.Signature,
      },
      evidence: w.evidenceFor(n),
    };
    expect(await w.verify(req)).toEqual({ ok: false, reason: "malformed-signature-input" });

    // Even with a P-256 signature, an Ed25519 key published at the keyid fails.
    w.publish(JSON.stringify({ address: "a@b", public_key:
      "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n" }), "application/json");
    expect(await w.verify(await w.request(n))).toEqual({
      ok: false, reason: "key-algorithm-not-p256",
    });
  });

  it("run 2b: a registered software P-256 key with no evidence fails", async () => {
    const w = world();
    const software = newKey();
    w.publish(didDoc(software.publicKey.export({ format: "jwk" })));
    const n = w.challenger.issue();
    expect(await w.verify(await w.request(n, { signer: software, evidence: null }))).toEqual({
      ok: false, reason: "evidence-missing",
    });
  });

  it("run 2b: a software key borrowing the TPM key's evidence fails", async () => {
    const w = world();
    const software = newKey();
    w.publish(didDoc(software.publicKey.export({ format: "jwk" })));
    const n = w.challenger.issue();
    const req = await w.request(n, { signer: software }); // evidence certifies the TPM key
    expect(await w.verify(req)).toEqual({ ok: false, reason: "jwk-mismatch" });
    expect(w.challenger.has(n)).toBe(true);
  });

  it("run 3: old evidence replayed against a new challenge fails", async () => {
    const w = world();
    const old = w.challenger.issue();
    const oldEvidence = w.evidenceFor(old);
    expect((await w.verify(await w.request(old, { evidence: oldEvidence }))).ok).toBe(true);

    const fresh = w.challenger.issue();
    const replay = await w.request(fresh, { evidence: oldEvidence });
    expect(await w.verify(replay)).toEqual({ ok: false, reason: "nonce-mismatch" });
    expect(w.challenger.has(fresh)).toBe(true);
  });
});

describe("verifyHardwareBoundRequest: other rejections", () => {
  it("rejects replay of the complete request", async () => {
    const w = world();
    const req = await w.request(w.challenger.issue());
    expect((await w.verify(req)).ok).toBe(true);
    expect(await w.verify(req)).toEqual({ ok: false, reason: "nonce-unknown" });
  });

  it("rejects an expired or never-issued nonce", async () => {
    const w = world();
    const n = w.challenger.issue();
    const req = await w.request(n);
    w.clock.t += 61;
    expect(await w.verify(req)).toEqual({ ok: false, reason: "nonce-unknown" });
    expect(await w.verify(await w.request(new Uint8Array(32).fill(9)))).toEqual({
      ok: false, reason: "nonce-unknown",
    });
  });

  it("rejects a signature that was not made by the published key", async () => {
    const w = world();
    const n = w.challenger.issue();
    const req = await w.request(n, { signer: newKey() });
    expect(await w.verify(req)).toEqual({ ok: false, reason: "signature-invalid" });
    expect(w.challenger.has(n)).toBe(true);
  });

  it("does not consume the nonce for a tampered request", async () => {
    const w = world();
    const n = w.challenger.issue();
    const req = await w.request(n);
    expect(await w.verify({ ...req, body: new TextEncoder().encode("{}") })).toEqual({
      ok: false, reason: "content-digest-mismatch",
    });
    expect(w.challenger.has(n)).toBe(true);
    expect((await w.verify(req)).ok).toBe(true);
  });

  it("rejects an AK that is not pinned, before fetching the keyid", async () => {
    const w = world();
    const n = w.challenger.issue();
    const req = await w.request(n);
    expect(await w.verify(req, () => undefined)).toEqual({ ok: false, reason: "ak-not-pinned" });
    expect(w.fetches()).toBe(0);
    expect(await w.verify(req, syntheticAk().akPem)).toEqual({
      ok: false, reason: "ak-not-pinned",
    });
  });

  it("looks the pinned AK up by keyid", async () => {
    const w = world();
    const req = await w.request(w.challenger.issue());
    const seen: string[] = [];
    const r = await w.verify(req, (k) => { seen.push(k); return w.ak.akPem; });
    expect(r.ok).toBe(true);
    expect(seen).toEqual([KEYID]);
  });

  it("rejects malformed evidence and missing headers", async () => {
    const w = world();
    const n = w.challenger.issue();
    expect(await w.verify(await w.request(n, { evidence: "{nope" }))).toEqual({
      ok: false, reason: "evidence-malformed",
    });
    const req = await w.request(n);
    expect(await w.verify({ ...req, headers: {} })).toEqual({
      ok: false, reason: "missing-headers",
    });
  });

  it("rejects a nonce parameter that is not a 32-byte challenge", async () => {
    const w = world();
    const req = await w.request(new Uint8Array(8).fill(1));
    expect(await w.verify(req)).toEqual({ ok: false, reason: "nonce-unknown" });
  });

  it("reports a keyid that cannot be resolved", async () => {
    const w = world();
    const req = await w.request(w.challenger.issue());
    const r = await verifyHardwareBoundRequest({
      request: req,
      challenger: w.challenger,
      pinnedAk: w.ak.akPem,
      resolve: { fetch: async () => new Response("no", { status: 404 }) },
      nowSeconds: NOW + 1,
    });
    expect(r).toEqual({ ok: false, reason: "key-resolution-failed" });
  });
});

describe("verifyHardwareBoundRequest: external appraiser", () => {
  it("runs after local checks, with the verified key and attestation", async () => {
    const w = world();
    const n = w.challenger.issue();
    let seen: Parameters<EvidenceAppraiser["appraise"]>[0] | undefined;
    const r = await w.verify(await w.request(n), w.ak.akPem, {
      appraise: async (input) => { seen = input; return { ok: true }; },
    });
    expect(r.ok).toBe(true);
    expect(seen?.keyid).toBe(KEYID);
    expect(Buffer.from(seen!.attest.extraData).equals(Buffer.from(n))).toBe(true);
  });

  it("can reject evidence that passed the local checks", async () => {
    const w = world();
    const r = await w.verify(await w.request(w.challenger.issue()), w.ak.akPem, {
      appraise: async () => ({ ok: false, reason: "policy" }),
    });
    expect(r).toEqual({ ok: false, reason: "appraisal-rejected" });
  });

  it("fails closed when the appraiser throws", async () => {
    const w = world();
    const r = await w.verify(await w.request(w.challenger.issue()), w.ak.akPem, {
      appraise: async () => { throw new Error("verifier down"); },
    });
    expect(r).toEqual({ ok: false, reason: "appraisal-failed" });
  });

  it("is never consulted when a local check already failed", async () => {
    const w = world();
    let called = false;
    const r = await w.verify(await w.request(w.challenger.issue(), { evidence: null }), w.ak.akPem, {
      appraise: async () => { called = true; return { ok: true }; },
    });
    expect(r).toEqual({ ok: false, reason: "evidence-missing" });
    expect(called).toBe(false);
  });
});
