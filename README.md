# @opena2a/a2a-idf

Reference TypeScript SDK for **A2A-IDF** — the Agent-to-Agent Identity Framework specified in [a2aproject/A2A#1496](https://github.com/a2aproject/A2A/pull/1496).

- **Spec:** A2A-IDF (PR #1496)
- **Conformance suite:** [`opena2a-org/a2a-idf-conformance`](https://github.com/opena2a-org/a2a-idf-conformance)
- **Reference implementation:** [AIM](https://github.com/opena2a-org/agent-identity-management)
- **Identity home:** https://opena2a.org/identity
- **License:** Apache-2.0
- **Runtime:** Node.js ≥ 24

## What this package does

Verifier-side first. Given a signed A2A request (RFC 9421 over Ed25519), this SDK answers four questions:

1. Is the signature valid against the keyid's published public key?
2. Has the request been replayed (stale `created`, seen `nonce`)?
3. What verification level applies (0 self-asserted / 1 domain-verified / 2 organization-verified)?
4. If the requesting agent is acting on behalf of someone else, does the delegation chain check out?

Signer-side is supported via a minimal `sign()` for clients that need to produce request signatures or build test fixtures.

An optional hardware-key path lets the signing key be a P-256 key inside a TPM 2.0, with the relying party checking that the key is TPM-resident for a challenge it issued. See [Hardware-key path](#hardware-key-path-tpm-20-p-256).

## Install

```bash
npm install @opena2a/a2a-idf
```

Runtime dependencies are exactly two: [`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes). No transitive cryptography deps; nothing pulls in OpenSSL FFI or `node-forge`. The hardware-key path adds no packages: it uses Node's built-in `node:crypto`, and the TPM host side shells out to [tpm2-tools](https://github.com/tpm2-software/tpm2-tools).

## Quick start

```ts
import {
  sign,
  verify,
  resolveKeyid,
  ReplayCache,
} from "@opena2a/a2a-idf";

// 1. Sign an outbound request.
const signed = sign({
  method: "POST",
  path: "/api/task",
  body: new TextEncoder().encode(JSON.stringify({ task: "summarize" })),
  params: {
    keyid: "https://acme.example/keys/agent-1",
    created: Math.floor(Date.now() / 1000),
    nonce: crypto.randomUUID().replace(/-/g, ""),
  },
  privateKey, // 32-byte Ed25519 seed
});

// 2. Verify an inbound request.
const { publicKey } = await resolveKeyid(
  "https://acme.example/keys/agent-1",
);
const replay = new ReplayCache();
const result = verify({
  method: "POST",
  path: "/api/task",
  body: requestBody,
  headers: {
    "content-digest": headers["content-digest"],
    "signature-input": headers["signature-input"],
    signature: headers["signature"],
  },
  publicKey,
  checkNonce: replay.check.bind(replay),
});
if (!result.ok) {
  // result.reason is one of:
  //   missing-headers, malformed-signature-input, malformed-signature,
  //   unsupported-component, content-digest-mismatch, content-digest-missing,
  //   content-digest-unsupported-algorithm,
  //   timestamp-too-old, timestamp-future-skew,
  //   replay-detected, signature-invalid
}
```

## Cross-implementation byte-match

This SDK byte-matches the Envoys signature/v1 §13 test vectors (spec v1.4.0, sha256 `5dcc855e…c21b2e9`). The vectors are vendored in [`vectors/rfc8032-7-1.json`](vectors/rfc8032-7-1.json), whose `envoysSpec` field records the specification URL, version, sha256 and fetch date.

| Vector | Method | Path | Body | Status |
|---|---|---|---|---|
| 1 | GET | `/api/health` | empty | ✓ matches `XUpjUHt36NbHgAZrQkFY2fSNUR19tgmRlGO1dBhaZDgBv4wb55qgJf2buv3wgnTYwtT+1sH2jzSbcgG6FLGKCA==` |
| 2 | POST | `/api/task` | summarize JSON | ✓ matches `i5tKcOHKhRTCztR2cazuzNAg9rPiRf47MKTOGve92Rs43gNmltuN5LVScedR6C08MGsQykMc7txJ21KCG8SEBQ==` |
| 3 | POST | `/api/echo` | `{}` | ✓ matches `m2besJKk6Q0MIwFoTENobvvHxFan1fUTv7bzY4EB6OjfIlktqwKa7r/Ab0tDDWFGjQ0CbALgvWGcQfzDr/GeBQ==` |

See [`test/rfc9421.test.ts`](test/rfc9421.test.ts). The keypair is RFC 8032 §7.1 Test 1, fixed for reproducibility across implementations.

## Usage

### Verification levels

```ts
import { level1, level2 } from "@opena2a/a2a-idf";

// Level 1 — domain-verified
const l1 = await level1({
  signatureVerified: result.ok,
  domain: "acme.example",
  expectedToken: "https://acme.example/keys/agent-1",
  dns: yourDnsResolver, // implements resolveTxt(name) → { records, ttlSeconds }
});
// l1.warnings includes "dns-ttl-above-cap:<n>s > 300s" when the
// `_a2a-identity` record TTL exceeds the cap.

// Level 2 — organization-verified (Level 1 + trusted attestations)
const l2 = await level2({
  ...l1Inputs,
  attestationArray: agentCard.attestations,
  attestationOpts: {
    resolveIssuerKey: async (issuerKeyid) =>
      (await resolveKeyid(issuerKeyid)).publicKey,
  },
  trustedIssuers: new Set(["https://attestor.example/keys/issuer-1"]),
});
```

### Delegation chains

```ts
import { verifyDelegationChain } from "@opena2a/a2a-idf";

const r = await verifyDelegationChain(agentCard.delegationChain, {
  resolveKey: async (keyid) => (await resolveKeyid(keyid)).publicKey,
  nowSeconds: Math.floor(Date.now() / 1000),
  maxDepth: 4,
});
if (r.ok) {
  console.log("effective scope:", r.effectiveScope);
}
```

Chain rules enforced: first link is a root (signed by the originating delegator); each subsequent link carries the previous link's `previousSignature`; scope narrows monotonically; expiry never widens; depth ≤ `maxDepth`; signing keys resolve through the same `resolveKey` callback.

### Dual-shape keyid resolution

`resolveKeyid()` dispatches on `Content-Type`:

- `application/did+json` → W3C DID Document with an Ed25519 verification method (`publicKeyMultibase` or `publicKeyJwk` with `crv: "Ed25519"`), or an EC P-256 `publicKeyJwk`.
- anything else → Envoys §6 compact form `{ address, public_key: <PEM SPKI> }`.

Both shapes return the same 32-byte raw Ed25519 key for Ed25519 documents (`algorithm: "ed25519"`), so callers can pass it directly to `verify({ publicKey })`. A P-256 document returns the 65-byte uncompressed point with `algorithm: "ecdsa-p256-sha256"`, for the hardware-key verifier below. Check `algorithm` before choosing a verifier.

### Hardware-key path (TPM 2.0, P-256)

```ts
import { NonceChallenger, verifyHardwareBoundRequest } from "@opena2a/a2a-idf";

const challenger = new NonceChallenger();
const nonce = challenger.issue(); // send to the host as the challenge

const result = await verifyHardwareBoundRequest({
  request: { method, authority, path, body, headers, evidence },
  challenger,
  pinnedAk: (keyid) => pinnedAks.get(keyid),
});
```

The request is signed with `ecdsa-p256-sha256` (RFC 9421), and the evidence is a `TPM2_Certify` of the signing key that carries the challenge nonce. Without valid evidence for the published key, the request is rejected. The Ed25519 `sign()` / `verify()` path is unchanged. Hosts use `@opena2a/a2a-idf/tpm-host`. The design, wire formats, failure reasons and limitations are in [docs/hardware-key.md](docs/hardware-key.md). The attestation key is pinned (no EK chain) and the reference setup uses a virtual TPM; read the limitations there.

## What this SDK does **not** ship at MVP

- General algorithm agility. Ed25519 is the default; ECDSA P-256 is supported only as the [hardware-key path](docs/hardware-key.md) with its own verifier.
- HTTP transport (consumers pass already-fetched bodies and headers).
- Software key generation / persistence (use a platform keychain or [`@opena2a/secretless`](https://github.com/opena2a-org/secretless)). TPM key generation is available through the hardware-key path.
- Browser bundle (Node 24+ only at v0.1).
- CLI verb wrappers.

These are scoped for `v0.2` and onward.

## Status

`v0.1` — MVP. Not yet published to npm. All acceptance criteria from the [A2A-IDF SDK pickup doc](https://github.com/opena2a-org/a2a-idf-conformance) are met locally; npm publication follows the canonical-suite composition fixture (`fixtures/composition/aim-did-rfc9421/signature-alone.json`) landing in `opena2a-org/a2a-idf-conformance` and an `opena2a.org/identity` page going live.

## Documentation

- [Contributing](docs/CONTRIBUTING.md): where byte-match fixtures and cross-implementation behavior changes are proposed.
- [Hardware-key path](docs/hardware-key.md): TPM 2.0 P-256 keys, evidence, nonce challenges and their limits.
