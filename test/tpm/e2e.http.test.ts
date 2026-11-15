// Full end-to-end run over real HTTP: a relying-party server (challenge
// endpoint, DID document at the keyid URL, protected endpoint) and an agent
// client whose signing key lives in the real TPM. Covers the plan's three
// runs plus the extra negatives. Skipped unless /dev/tpmrm0 is usable.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";

import { NonceChallenger } from "../../src/tpm/challenge.js";
import { encodeEvidenceBundle } from "../../src/tpm/evidence.js";
import { TpmHost, type HardwareKeyInfo } from "../../src/tpm/host.js";
import { verifyHardwareBoundRequest } from "../../src/tpm/policy.js";
import { signEcdsaP256, type P256Signer } from "../../src/rfc9421-p256.js";
import { tpmAvailable } from "./helpers.js";

const b64u = (b: Uint8Array): string => Buffer.from(b).toString("base64url");

interface Reply {
  status: number;
  body: { ok: boolean; reason?: string };
}

describe.skipIf(!tpmAvailable())("end to end over HTTP with a real TPM", () => {
  const host = new TpmHost({ akHandle: 0x81010030, keyHandle: 0x81010031 });
  let info: HardwareKeyInfo;
  let server: Server;
  let base: string;
  const clock = { t: Math.floor(Date.now() / 1000) };
  const challenger = new NonceChallenger({ ttlSeconds: 30, now: () => clock.t });
  // The key the relying party currently has registered at the keyid URL.
  let registeredJwk: unknown;

  beforeAll(async () => {
    info = await host.provision({ replace: true });
    registeredJwk = info.jwk;

    server = createServer((req, res) => {
      const send = (status: number, type: string, body: string): void => {
        res.writeHead(status, { "content-type": type });
        res.end(body);
      };
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", async () => {
        if (req.method === "GET" && req.url === "/.well-known/did.json") {
          return send(200, "application/did+json", JSON.stringify({
            id: "did:web:agent.test",
            verificationMethod: [{
              id: "did:web:agent.test#k", type: "JsonWebKey2020",
              controller: "did:web:agent.test", publicKeyJwk: registeredJwk,
            }],
            assertionMethod: ["did:web:agent.test#k"],
          }));
        }
        if (req.method === "POST" && req.url === "/challenge") {
          return send(200, "application/json", JSON.stringify({ nonce: b64u(challenger.issue()) }));
        }
        if (req.method === "POST" && req.url === "/a2a") {
          const evidence = req.headers["tpm-evidence"];
          const result = await verifyHardwareBoundRequest({
            request: {
              method: req.method,
              authority: req.headers.host ?? "",
              path: req.url,
              body: new Uint8Array(Buffer.concat(chunks)),
              headers: {
                "content-digest": req.headers["content-digest"] as string | undefined,
                "signature-input": req.headers["signature-input"] as string | undefined,
                signature: req.headers.signature as string | undefined,
              },
              ...(typeof evidence === "string" ? { evidence } : {}),
            },
            challenger,
            pinnedAk: info.akPem,
            resolve: {},
            nowSeconds: clock.t,
          });
          return send(
            result.ok ? 200 : 401,
            "application/json",
            JSON.stringify(result.ok ? { ok: true } : { ok: false, reason: result.reason }),
          );
        }
        send(404, "text/plain", "not found");
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }, 120_000);

  afterAll(async () => {
    await new Promise<void>((r) => server?.close(() => r()));
    await host.release();
  }, 60_000);

  const keyid = (): string => `${base}/.well-known/did.json`;
  const challenge = async (): Promise<Uint8Array> => {
    const r = await fetch(`${base}/challenge`, { method: "POST" });
    return new Uint8Array(Buffer.from(((await r.json()) as { nonce: string }).nonce, "base64url"));
  };

  /** Builds and sends a signed request; returns the signed headers for replays. */
  async function call(opts: {
    nonce: Uint8Array;
    signer?: P256Signer;
    evidence?: string;
    body?: string;
  }): Promise<{ reply: Reply; headers: Record<string, string>; body: string }> {
    const body = opts.body ?? '{"task":"run"}';
    const url = new URL(base);
    const h = await signEcdsaP256(
      {
        method: "POST", authority: url.host, path: "/a2a",
        body: new TextEncoder().encode(body),
        params: { keyid: keyid(), created: clock.t, expires: clock.t + 120, nonce: b64u(opts.nonce) },
      },
      opts.signer ?? host.signer,
    );
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "content-digest": h["Content-Digest"],
      "signature-input": h["Signature-Input"],
      signature: h.Signature,
      ...(opts.evidence !== undefined ? { "tpm-evidence": opts.evidence } : {}),
    };
    return { reply: await send(headers, body), headers, body };
  }

  async function send(headers: Record<string, string>, body: string): Promise<Reply> {
    const r = await fetch(`${base}/a2a`, { method: "POST", headers, body });
    return { status: r.status, body: (await r.json()) as Reply["body"] };
  }

  const evidenceFor = async (nonce: Uint8Array): Promise<string> =>
    encodeEvidenceBundle(await host.certify(nonce));

  const softwareKey = () => {
    const kp = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const signer: P256Signer = (m) =>
      cryptoSign("sha256", m, { key: kp.privateKey, dsaEncoding: "ieee-p1363" });
    return { signer, jwk: kp.publicKey.export({ format: "jwk" }) };
  };

  it("run 1: the TPM-resident key with a fresh nonce is accepted", async () => {
    registeredJwk = info.jwk;
    const nonce = await challenge();
    const { reply } = await call({ nonce, evidence: await evidenceFor(nonce) });
    expect(reply).toEqual({ status: 200, body: { ok: true } });
  }, 60_000);

  it("run 2a: a registered software P-256 key with no evidence is rejected", async () => {
    const sw = softwareKey();
    registeredJwk = sw.jwk;
    const nonce = await challenge();
    const { reply } = await call({ nonce, signer: sw.signer });
    expect(reply).toEqual({ status: 401, body: { ok: false, reason: "evidence-missing" } });
  });

  it("run 2b: a software key presenting the TPM key's evidence is rejected", async () => {
    const sw = softwareKey();
    registeredJwk = sw.jwk;
    const nonce = await challenge();
    const { reply } = await call({ nonce, signer: sw.signer, evidence: await evidenceFor(nonce) });
    expect(reply).toEqual({ status: 401, body: { ok: false, reason: "jwk-mismatch" } });
  }, 60_000);

  it("run 3: old evidence replayed against a new challenge is rejected", async () => {
    registeredJwk = info.jwk;
    const oldNonce = await challenge();
    const oldEvidence = await evidenceFor(oldNonce);
    const freshNonce = await challenge();
    const { reply } = await call({ nonce: freshNonce, evidence: oldEvidence });
    expect(reply).toEqual({ status: 401, body: { ok: false, reason: "nonce-mismatch" } });
    // The fresh challenge is still usable by the legitimate host.
    const again = await call({ nonce: freshNonce, evidence: await evidenceFor(freshNonce) });
    expect(again.reply.status).toBe(200);
  }, 60_000);

  it("a captured request cannot be replayed after it succeeded", async () => {
    registeredJwk = info.jwk;
    const nonce = await challenge();
    const first = await call({ nonce, evidence: await evidenceFor(nonce) });
    expect(first.reply.status).toBe(200);
    expect(await send(first.headers, first.body)).toEqual({
      status: 401, body: { ok: false, reason: "nonce-unknown" },
    });
  }, 60_000);

  it("rejects a challenge that expired before use", async () => {
    registeredJwk = info.jwk;
    const nonce = await challenge();
    const evidence = await evidenceFor(nonce);
    clock.t += 31;
    try {
      const { reply } = await call({ nonce, evidence });
      expect(reply).toEqual({ status: 401, body: { ok: false, reason: "nonce-unknown" } });
    } finally {
      clock.t -= 31;
    }
  }, 60_000);

  it("rejects a body altered after signing", async () => {
    registeredJwk = info.jwk;
    const nonce = await challenge();
    const sent = await call({ nonce, evidence: await evidenceFor(nonce), body: '{"task":"run"}' });
    expect(sent.reply.status).toBe(200);
    // Same signed headers, different body. The digest check runs before the
    // nonce is looked at, so this is a digest failure, not a replay.
    expect(await send(sent.headers, '{"task":"evil"}')).toEqual({
      status: 401, body: { ok: false, reason: "content-digest-mismatch" },
    });
  }, 90_000);
});
