// Policy for the hardware-key path: accept a request only if it is signed by
// a P-256 key that a pinned attestation key (AK) certified, for a challenge
// this relying party issued, as being TPM-resident.
//
// This is the glue over the individual checks. A valid ecdsa-p256-sha256
// signature alone proves possession of a P-256 key, which a software key also
// has. The policy therefore additionally requires, in this order:
//   1. The Signature-Input is the P-256 profile (./rfc9421-p256.ts).
//   2. Evidence is present and well formed (a request with none is rejected:
//      "no hardware evidence" and "software P-256 key" both end here).
//   3. The AK is pinned for this keyid, decided before any network access, so
//      a hostile keyid URL is not fetched unless the caller has pinned an AK
//      for it.
//   4. The keyid resolves to a P-256 key (an Ed25519 key is rejected).
//   5. The request signature verifies under that key.
//   6. The evidence binds that same key (name, fixedTPM/fixedParent, JWK
//      match) to the challenge nonce, under the pinned AK.
//
// The challenge nonce doubles as the RFC 9421 `nonce` parameter, written as
// base64url of the 32 challenge bytes. That ties the evidence to this signed
// request: evidence answering an older challenge fails `nonce-mismatch`
// against a new one. The nonce is consumed only when every check passes.
//
// Not covered: a live relay, where an attacker forwards a legitimate host's
// fresh request and evidence to the same target. Also inherits the limits in
// ./binding.ts (pinned AK, no EK chain, virtual TPM is not tamper resistant).

import type { KeyObject } from "node:crypto";

import { resolveKeyid, type ResolveOptions } from "../keyid-resolver.js";
import { p256JwkFromPoint } from "../p256.js";
import {
  parseP256SignatureInput,
  verifyEcdsaP256,
  type P256SignatureParams,
  type P256VerifyFailureReason,
} from "../rfc9421-p256.js";
import {
  NONCE_BYTES,
  verifyChallengedEvidence,
  type ChallengedEvidenceFailureReason,
  type NonceChallenger,
} from "./challenge.js";
import { decodeEvidenceBundle, EvidenceFormatError } from "./evidence.js";
import type { TpmCertifyAttest, TpmEccPublic } from "./structures.js";

export type PinnedAk = KeyObject | string;

export interface HardwareBoundRequest {
  method: string;
  authority: string;
  path: string;
  body: Uint8Array;
  headers: {
    "content-digest"?: string;
    "signature-input"?: string;
    signature?: string;
  };
  /** The encoded evidence bundle (see `encodeEvidenceBundle`), if any. */
  evidence?: string;
}

export interface VerifyHardwareBoundRequestInputs {
  request: HardwareBoundRequest;
  challenger: NonceChallenger;
  /**
   * The trusted AK, or a lookup by keyid. A lookup that returns undefined
   * rejects the request before the keyid URL is fetched.
   */
  pinnedAk: PinnedAk | ((keyid: string) => PinnedAk | undefined);
  /** Options for `resolveKeyid` (fetch override, size cap, abort signal). */
  resolve?: ResolveOptions;
  maxAgeSeconds?: number;
  maxSkewSeconds?: number;
  /** Wall-clock now in seconds; defaults to the current time. */
  nowSeconds?: number;
}

export type HardwareBoundFailureReason =
  | P256VerifyFailureReason
  | ChallengedEvidenceFailureReason
  | "evidence-missing"
  | "evidence-malformed"
  | "key-resolution-failed"
  | "key-algorithm-not-p256";

export type HardwareBoundResult =
  | {
      ok: true;
      keyid: string;
      params: P256SignatureParams;
      /** The certified TPM key and the signed Certify attestation. */
      key: TpmEccPublic;
      attest: TpmCertifyAttest;
    }
  | { ok: false; reason: HardwareBoundFailureReason };

const fail = (reason: HardwareBoundFailureReason): HardwareBoundResult => ({
  ok: false,
  reason,
});

/** Decodes the signed `nonce` parameter back to the challenge bytes. */
function challengeFromParam(nonce: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]{43}$/.test(nonce)) return undefined;
  const bytes = new Uint8Array(Buffer.from(nonce, "base64url"));
  return bytes.byteLength === NONCE_BYTES ? bytes : undefined;
}

export async function verifyHardwareBoundRequest(
  inputs: VerifyHardwareBoundRequestInputs,
): Promise<HardwareBoundResult> {
  const { request, challenger } = inputs;

  const sigInput = request.headers["signature-input"];
  if (sigInput === undefined || request.headers.signature === undefined) {
    return fail("missing-headers");
  }
  const params = parseP256SignatureInput(sigInput);
  if (params === null) return fail("malformed-signature-input");

  if (request.evidence === undefined) return fail("evidence-missing");
  let bundle;
  try {
    bundle = decodeEvidenceBundle(request.evidence);
  } catch (e) {
    if (e instanceof EvidenceFormatError) return fail("evidence-malformed");
    throw e;
  }

  const pinnedAk =
    typeof inputs.pinnedAk === "function"
      ? inputs.pinnedAk(params.keyid)
      : inputs.pinnedAk;
  if (pinnedAk === undefined) return fail("ak-not-pinned");

  let resolved;
  try {
    resolved = await resolveKeyid(params.keyid, inputs.resolve);
  } catch {
    return fail("key-resolution-failed");
  }
  if (resolved.algorithm !== "ecdsa-p256-sha256") {
    return fail("key-algorithm-not-p256");
  }

  const nonceBytes = challengeFromParam(params.nonce);
  if (nonceBytes === undefined) return fail("nonce-unknown");

  const signature = verifyEcdsaP256({
    method: request.method,
    authority: request.authority,
    path: request.path,
    body: request.body,
    headers: request.headers,
    publicKey: resolved.publicKey,
    ...(inputs.maxAgeSeconds !== undefined
      ? { maxAgeSeconds: inputs.maxAgeSeconds }
      : {}),
    ...(inputs.maxSkewSeconds !== undefined
      ? { maxSkewSeconds: inputs.maxSkewSeconds }
      : {}),
    ...(inputs.nowSeconds !== undefined ? { nowSeconds: inputs.nowSeconds } : {}),
  });
  if (!signature.ok) return fail(signature.reason);

  const evidence = verifyChallengedEvidence({
    challenger,
    bundle,
    pinnedAk,
    jwk: p256JwkFromPoint(resolved.publicKey),
    nonce: nonceBytes,
  });
  if (!evidence.ok) return fail(evidence.reason);

  return {
    ok: true,
    keyid: params.keyid,
    params: signature.params,
    key: evidence.key,
    attest: evidence.attest,
  };
}
