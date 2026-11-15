// ECDSA signature encoding helpers for the P-256 / TPM path.
//
// RFC 9421 §3.3.4 (ecdsa-p256-sha256) requires the signature value to be the
// raw concatenation r || s (64 bytes, each big-endian and zero-padded to 32
// bytes). `tpm2_sign -f plain` and OpenSSL emit ASN.1 DER instead, whose
// INTEGERs are minimal-length (so r or s may be shorter than 32 bytes) and
// carry a 0x00 pad when the top bit is set (so they may be 33 bytes).
// Mixing the two encodings produces signatures that fail verification, which
// makes this conversion a likely source of bugs; keep it strict and tested.

export const P256_COORD_BYTES = 32;

export class EcdsaEncodingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EcdsaEncodingError";
  }
}

/** Left-pads big-endian `r` and `s` to `size` bytes each and concatenates. */
export function rsToRaw(
  r: Uint8Array,
  s: Uint8Array,
  size: number = P256_COORD_BYTES,
): Uint8Array {
  const out = new Uint8Array(size * 2);
  out.set(fit(r, size, "r"), 0);
  out.set(fit(s, size, "s"), size);
  return out;
}

/**
 * Converts a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s })
 * to raw r || s. Rejects anything that is not strict DER for two positive
 * integers that fit in `size` bytes.
 */
export function derToRaw(
  der: Uint8Array,
  size: number = P256_COORD_BYTES,
): Uint8Array {
  let pos = 0;
  const byte = (): number => {
    const b = der[pos];
    if (b === undefined) throw new EcdsaEncodingError("DER signature truncated");
    pos++;
    return b;
  };
  const length = (): number => {
    const first = byte();
    if (first < 0x80) return first;
    if (first !== 0x81) {
      throw new EcdsaEncodingError("unsupported DER length encoding");
    }
    const len = byte();
    if (len < 0x80) throw new EcdsaEncodingError("non-minimal DER length");
    return len;
  };
  const integer = (name: string): Uint8Array => {
    if (byte() !== 0x02) {
      throw new EcdsaEncodingError(`DER ${name} is not an INTEGER`);
    }
    const len = length();
    if (len === 0 || pos + len > der.byteLength) {
      throw new EcdsaEncodingError(`DER ${name} has an invalid length`);
    }
    const value = der.subarray(pos, pos + len);
    pos += len;
    if (value[0]! & 0x80) {
      throw new EcdsaEncodingError(`DER ${name} is negative`);
    }
    if (value.length > 1 && value[0] === 0x00 && !(value[1]! & 0x80)) {
      throw new EcdsaEncodingError(`DER ${name} has a non-minimal encoding`);
    }
    return value;
  };

  if (byte() !== 0x30) {
    throw new EcdsaEncodingError("DER signature is not a SEQUENCE");
  }
  const seqLen = length();
  if (pos + seqLen !== der.byteLength) {
    throw new EcdsaEncodingError("DER signature length mismatch");
  }
  const r = integer("r");
  const s = integer("s");
  if (pos !== der.byteLength) {
    throw new EcdsaEncodingError("trailing bytes after DER signature");
  }
  return rsToRaw(r, s, size);
}

/** Converts raw r || s to DER (SEQUENCE { INTEGER r, INTEGER s }). */
export function rawToDer(
  raw: Uint8Array,
  size: number = P256_COORD_BYTES,
): Uint8Array {
  if (raw.byteLength !== size * 2) {
    throw new EcdsaEncodingError(
      `raw signature must be ${size * 2} bytes, got ${raw.byteLength}`,
    );
  }
  const body = concat(
    derInteger(raw.subarray(0, size)),
    derInteger(raw.subarray(size)),
  );
  const header =
    body.length < 0x80
      ? Uint8Array.of(0x30, body.length)
      : Uint8Array.of(0x30, 0x81, body.length);
  return concat(header, body);
}

function derInteger(value: Uint8Array): Uint8Array {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0x00) start++;
  const trimmed = value.subarray(start);
  const pad = trimmed[0]! & 0x80 ? 1 : 0;
  const out = new Uint8Array(2 + pad + trimmed.length);
  out[0] = 0x02;
  out[1] = pad + trimmed.length;
  out.set(trimmed, 2 + pad);
  return out;
}

function fit(value: Uint8Array, size: number, name: string): Uint8Array {
  let start = 0;
  while (start < value.length && value[start] === 0x00) start++;
  const trimmed = value.subarray(start);
  if (trimmed.length > size) {
    throw new EcdsaEncodingError(
      `${name} is ${trimmed.length} bytes, expected at most ${size}`,
    );
  }
  const out = new Uint8Array(size);
  out.set(trimmed, size - trimmed.length);
  return out;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
