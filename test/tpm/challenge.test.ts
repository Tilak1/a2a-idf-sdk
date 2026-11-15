import { describe, it, expect } from "vitest";
import { createPublicKey } from "node:crypto";

import {
  NONCE_BYTES,
  NonceChallenger,
  verifyChallengedEvidence,
} from "../../src/tpm/challenge.js";
import type { TpmEvidenceBundle } from "../../src/tpm/evidence.js";
import { keyJwk, syntheticAk } from "./helpers.js";

const clock = (start = 1000) => {
  let t = start;
  return { now: () => t, advance: (s: number) => (t += s) };
};

describe("NonceChallenger", () => {
  it("issues distinct 32-byte random nonces", () => {
    const c = new NonceChallenger();
    const a = c.issue();
    const b = c.issue();
    expect(a.length).toBe(NONCE_BYTES);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it("consumes a nonce exactly once", () => {
    const c = new NonceChallenger();
    const n = c.issue();
    expect(c.has(n)).toBe(true);
    expect(c.has(n)).toBe(true); // has() does not consume
    expect(c.consume(n)).toBe(true);
    expect(c.consume(n)).toBe(false);
    expect(c.has(n)).toBe(false);
  });

  it("never accepts a nonce it did not issue", () => {
    const c = new NonceChallenger();
    c.issue();
    expect(c.consume(new Uint8Array(NONCE_BYTES))).toBe(false);
    expect(c.consume(new Uint8Array(0))).toBe(false);
  });

  it("expires nonces after the TTL", () => {
    const t = clock();
    const c = new NonceChallenger({ ttlSeconds: 60, now: t.now });
    const n = c.issue();
    t.advance(59);
    expect(c.has(n)).toBe(true);
    t.advance(1);
    expect(c.has(n)).toBe(false);
    expect(c.consume(n)).toBe(false);
    expect(c.size()).toBe(0);
  });

  it("drops the oldest outstanding nonce at capacity", () => {
    const c = new NonceChallenger({ capacity: 2 });
    const [a, b, d] = [c.issue(), c.issue(), c.issue()] as const;
    expect(c.has(a)).toBe(false);
    expect(c.has(b)).toBe(true);
    expect(c.has(d)).toBe(true);
    expect(c.size()).toBe(2);
  });
});

describe("verifyChallengedEvidence", () => {
  const setup = () => {
    const ak = syntheticAk();
    const challenger = new NonceChallenger();
    const evidenceFor = (nonce: Uint8Array): TpmEvidenceBundle => ({
      ...ak.make({ extraData: nonce }),
      akPublic: new Uint8Array(
        createPublicKey(ak.akPem).export({ format: "der", type: "spki" }),
      ),
    });
    const verify = (
      bundle: TpmEvidenceBundle,
      extra: { nonce?: Uint8Array } = {},
    ) =>
      verifyChallengedEvidence({
        challenger,
        bundle,
        pinnedAk: ak.akPem,
        jwk: keyJwk,
        ...extra,
      });
    return { ak, challenger, evidenceFor, verify };
  };

  it("passes for the original key and a fresh nonce, then rejects a replay", () => {
    const { challenger, evidenceFor, verify } = setup();
    const n = challenger.issue();
    const ev = evidenceFor(n);
    expect(verify(ev).ok).toBe(true);
    expect(challenger.has(n)).toBe(false);
    expect(verify(ev)).toEqual({ ok: false, reason: "nonce-unknown" });
  });

  it("rejects old evidence replayed against a new challenge (explicit nonce)", () => {
    const { challenger, evidenceFor, verify } = setup();
    const old = challenger.issue();
    const oldEvidence = evidenceFor(old);
    expect(verify(oldEvidence).ok).toBe(true);

    const fresh = challenger.issue();
    expect(verify(oldEvidence, { nonce: fresh })).toEqual({
      ok: false,
      reason: "nonce-mismatch",
    });
    expect(challenger.has(fresh)).toBe(true); // a failed attempt does not burn it
  });

  it("rejects evidence for a nonce that was never issued", () => {
    const { evidenceFor, verify } = setup();
    expect(verify(evidenceFor(new Uint8Array(NONCE_BYTES).fill(7)))).toEqual({
      ok: false,
      reason: "nonce-unknown",
    });
  });

  it("rejects evidence whose challenge has expired", () => {
    const t = clock();
    const ak = syntheticAk();
    const challenger = new NonceChallenger({ ttlSeconds: 30, now: t.now });
    const n = challenger.issue();
    t.advance(30);
    const result = verifyChallengedEvidence({
      challenger,
      bundle: {
        ...ak.make({ extraData: n }),
        akPublic: new Uint8Array(
          createPublicKey(ak.akPem).export({ format: "der", type: "spki" }),
        ),
      },
      pinnedAk: ak.akPem,
      jwk: keyJwk,
    });
    expect(result).toEqual({ ok: false, reason: "nonce-unknown" });
  });

  it("rejects a bundle whose AK is not the pinned one, without burning the nonce", () => {
    const { challenger, evidenceFor } = setup();
    const n = challenger.issue();
    const other = syntheticAk();
    const result = verifyChallengedEvidence({
      challenger,
      bundle: evidenceFor(n),
      pinnedAk: other.akPem,
      jwk: keyJwk,
    });
    expect(result).toEqual({ ok: false, reason: "ak-not-pinned" });
    expect(challenger.has(n)).toBe(true);
  });

  it("does not consume the nonce when the evidence is forged", () => {
    const { challenger, evidenceFor, verify } = setup();
    const n = challenger.issue();
    const forged = evidenceFor(n);
    const certInfo = Uint8Array.from(forged.certInfo);
    certInfo[certInfo.length - 1] ^= 1;
    expect(verify({ ...forged, certInfo })).toEqual({
      ok: false,
      reason: "ak-signature-invalid",
    });
    expect(challenger.has(n)).toBe(true);
    expect(verify(forged).ok).toBe(true);
  });

  it("rejects a JWK that is not the certified key and keeps the nonce", () => {
    const { ak, challenger, evidenceFor } = setup();
    const n = challenger.issue();
    const wrongJwk = createPublicKey(ak.akPem).export({ format: "jwk" });
    const result = verifyChallengedEvidence({
      challenger,
      bundle: evidenceFor(n),
      pinnedAk: ak.akPem,
      jwk: wrongJwk,
    });
    expect(result).toEqual({ ok: false, reason: "jwk-mismatch" });
    expect(challenger.has(n)).toBe(true);
  });

  it("reports an unparseable Certify structure as malformed", () => {
    const { evidenceFor, challenger, ak } = setup();
    const ev = { ...evidenceFor(challenger.issue()), certInfo: new Uint8Array(3) };
    expect(
      verifyChallengedEvidence({
        challenger,
        bundle: ev,
        pinnedAk: ak.akPem,
        jwk: keyJwk,
      }),
    ).toEqual({ ok: false, reason: "malformed-evidence" });
  });
});
