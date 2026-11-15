// Evidence bundle for the TPM P-256 hardware-key path: the data a host sends
// the relying party to prove its signing key is TPM-resident.
//
// Wire format: a JSON object with base64url (unpadded) fields,
//   { "v": 1, "certInfo": ..., "certSignature": ..., "keyPublic": ...,
//     "akPublic": ... }
// where
//   certInfo       TPMS_ATTEST from TPM2_Certify
//   certSignature  TPMT_SIGNATURE by the AK over certInfo
//   keyPublic      TPM2B_PUBLIC of the certified signing key
//   akPublic       the AK's public key as SPKI DER
//
// The bundle is attacker-controlled input. Decoding is strict (exact field
// set, canonical base64url, size caps) and only splits the bytes; the TPM
// structures inside are validated by ./structures.ts and ./binding.ts.
//
// `akPublic` is informational: it lets the relying party pick the matching
// pinned AK. It must never be used as the trust anchor itself. Use
// `akMatchesPin` to compare it against the key the relying party pinned.

import { createPublicKey, timingSafeEqual, type KeyObject } from "node:crypto";

export const EVIDENCE_VERSION = 1;

/** Upper bound on the encoded bundle, checked before JSON parsing. */
export const MAX_EVIDENCE_TEXT_BYTES = 16 * 1024;
const MAX_FIELD_BYTES = 4 * 1024;

export interface TpmEvidenceBundle {
  certInfo: Uint8Array;
  certSignature: Uint8Array;
  keyPublic: Uint8Array;
  akPublic: Uint8Array;
}

export class EvidenceFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvidenceFormatError";
  }
}

const FIELDS = ["certInfo", "certSignature", "keyPublic", "akPublic"] as const;

const encode = (b: Uint8Array): string => Buffer.from(b).toString("base64url");

export function encodeEvidenceBundle(bundle: TpmEvidenceBundle): string {
  const out: Record<string, string | number> = { v: EVIDENCE_VERSION };
  for (const f of FIELDS) out[f] = encode(bundle[f]);
  return JSON.stringify(out);
}

function decodeField(name: string, value: unknown): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new EvidenceFormatError(`${name} is not unpadded base64url`);
  }
  const bytes = new Uint8Array(Buffer.from(value, "base64url"));
  // Re-encoding rejects non-canonical forms (stray trailing bits).
  if (encode(bytes) !== value) {
    throw new EvidenceFormatError(`${name} is not canonical base64url`);
  }
  if (bytes.byteLength > MAX_FIELD_BYTES) {
    throw new EvidenceFormatError(`${name} exceeds ${MAX_FIELD_BYTES} bytes`);
  }
  return bytes;
}

export function decodeEvidenceBundle(text: string): TpmEvidenceBundle {
  if (typeof text !== "string" || Buffer.byteLength(text) > MAX_EVIDENCE_TEXT_BYTES) {
    throw new EvidenceFormatError("evidence is not a string within the size limit");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new EvidenceFormatError("evidence is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new EvidenceFormatError("evidence is not a JSON object");
  }
  const obj = parsed as Record<string, unknown>;
  const allowed = new Set<string>(["v", ...FIELDS]);
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) throw new EvidenceFormatError(`unknown field ${key}`);
  }
  if (obj.v !== EVIDENCE_VERSION) {
    throw new EvidenceFormatError(`unsupported evidence version ${String(obj.v)}`);
  }
  return {
    certInfo: decodeField("certInfo", obj.certInfo),
    certSignature: decodeField("certSignature", obj.certSignature),
    keyPublic: decodeField("keyPublic", obj.keyPublic),
    akPublic: decodeField("akPublic", obj.akPublic),
  };
}

/**
 * True when the bundle's AK public key (SPKI DER) is the pinned AK. Anything
 * unparseable, or not byte-identical after normalisation, is a non-match.
 */
export function akMatchesPin(
  akPublic: Uint8Array,
  pinnedAk: KeyObject | string,
): boolean {
  try {
    const spki = (k: KeyObject): Buffer =>
      k.export({ format: "der", type: "spki" });
    const claimed = spki(
      createPublicKey({ key: Buffer.from(akPublic), format: "der", type: "spki" }),
    );
    const pinned = spki(
      typeof pinnedAk === "string" ? createPublicKey(pinnedAk) : pinnedAk,
    );
    return claimed.byteLength === pinned.byteLength && timingSafeEqual(claimed, pinned);
  } catch {
    return false;
  }
}
