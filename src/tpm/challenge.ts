// Relying-party nonce challenges for the TPM evidence flow (RFC 9334
// background-check model). The relying party issues a fresh random nonce, the
// host passes it to TPM2_Certify as qualifyingData, and the relying party
// accepts the resulting evidence only if that same nonce is still outstanding.
//
// A nonce is single-use and short-lived: it is consumed on the first
// successful verification and discarded after `ttlSeconds` regardless.
//
// In-memory and single-process, like ReplayCache. A verifier behind a load
// balancer needs a shared store with the same issue/has/consume semantics.
// When the table is full the oldest outstanding challenge is dropped, so the
// endpoint that issues challenges should be rate limited by the caller.

import { randomBytes, type KeyObject } from "node:crypto";

import { akMatchesPin, type TpmEvidenceBundle } from "./evidence.js";
import {
  verifyTpmBinding,
  type BindingFailureReason,
  type BindingResult,
  type EcP256Jwk,
} from "./binding.js";
import { TpmFormatError, parseCertifyAttest } from "./structures.js";

export const NONCE_BYTES = 32;

export interface NonceChallengerOptions {
  /** Seconds an issued nonce stays valid. Defaults to 60. */
  ttlSeconds?: number;
  /** Max outstanding nonces before the oldest is dropped. Defaults to 4096. */
  capacity?: number;
  /** Injected clock; defaults to `Date.now() / 1000`. */
  now?: () => number;
}

const key = (nonce: Uint8Array): string => Buffer.from(nonce).toString("base64url");

export class NonceChallenger {
  private readonly ttl: number;
  private readonly capacity: number;
  private readonly now: () => number;
  private readonly outstanding: Map<string, number> = new Map();

  constructor(options: NonceChallengerOptions = {}) {
    this.ttl = options.ttlSeconds ?? 60;
    this.capacity = options.capacity ?? 4096;
    this.now = options.now ?? (() => Date.now() / 1000);
  }

  /** Issues a fresh random challenge nonce (32 bytes). */
  issue(): Uint8Array {
    this.evictExpired();
    if (this.outstanding.size >= this.capacity) {
      const oldest = this.outstanding.keys().next().value;
      if (oldest !== undefined) this.outstanding.delete(oldest);
    }
    const nonce = new Uint8Array(randomBytes(NONCE_BYTES));
    this.outstanding.set(key(nonce), this.now() + this.ttl);
    return nonce;
  }

  /** True if `nonce` was issued, is unexpired and unconsumed. Does not consume. */
  has(nonce: Uint8Array): boolean {
    this.evictExpired();
    return this.outstanding.has(key(nonce));
  }

  /** Consumes `nonce`: true exactly once for a live, issued nonce. */
  consume(nonce: Uint8Array): boolean {
    this.evictExpired();
    return this.outstanding.delete(key(nonce));
  }

  size(): number {
    this.evictExpired();
    return this.outstanding.size;
  }

  private evictExpired(): void {
    const now = this.now();
    for (const [k, expiresAt] of this.outstanding) {
      if (expiresAt <= now) this.outstanding.delete(k);
      else break; // insertion-ordered with a fixed TTL, so expiry is monotonic
    }
  }
}

export type ChallengedEvidenceFailureReason =
  | BindingFailureReason
  | "ak-not-pinned"
  | "nonce-unknown";

export type ChallengedEvidenceResult =
  | Extract<BindingResult, { ok: true }>
  | { ok: false; reason: ChallengedEvidenceFailureReason };

export interface VerifyChallengedEvidenceInputs {
  challenger: NonceChallenger;
  bundle: TpmEvidenceBundle;
  /** The AK the relying party trusts for this host. */
  pinnedAk: KeyObject | string;
  /** The key the signer publishes (e.g. from the DID document at the keyid). */
  jwk: EcP256Jwk;
  /**
   * The nonce this request claims to answer, when the relying party tracks it
   * out of band (a session, or the RFC 9421 `nonce` parameter). It must be
   * outstanding and the evidence must carry exactly it. When omitted, the
   * nonce inside the signed Certify structure is used and must be outstanding.
   */
  nonce?: Uint8Array;
}

/**
 * Verifies an evidence bundle against a pinned AK and an issued challenge.
 * The nonce is consumed only when every check passes, so replayed evidence
 * fails with `nonce-unknown` (or `nonce-mismatch` when `nonce` is supplied)
 * and forged evidence cannot burn a victim's outstanding challenge. A failed
 * attempt leaves an explicitly named `nonce` outstanding until its TTL.
 */
export function verifyChallengedEvidence(
  inputs: VerifyChallengedEvidenceInputs,
): ChallengedEvidenceResult {
  const { challenger, bundle, pinnedAk, jwk } = inputs;

  if (!akMatchesPin(bundle.akPublic, pinnedAk)) {
    return { ok: false, reason: "ak-not-pinned" };
  }

  let nonce = inputs.nonce;
  if (nonce === undefined) {
    try {
      nonce = parseCertifyAttest(bundle.certInfo).extraData;
    } catch (e) {
      if (e instanceof TpmFormatError) {
        return { ok: false, reason: "malformed-evidence" };
      }
      throw e;
    }
  }
  if (nonce.byteLength === 0 || !challenger.has(nonce)) {
    return { ok: false, reason: "nonce-unknown" };
  }

  const result = verifyTpmBinding({
    evidence: bundle,
    akPublicKey: pinnedAk,
    expectedNonce: nonce,
    jwk,
  });
  if (!result.ok) return result;

  // Atomic with the has() above: nothing awaits in between.
  if (!challenger.consume(nonce)) return { ok: false, reason: "nonce-unknown" };
  return result;
}
