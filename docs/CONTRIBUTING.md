# Contributing

The conformance suite ([`opena2a-org/a2a-idf-conformance`](https://github.com/opena2a-org/a2a-idf-conformance)) is the canonical home for cross-implementation byte-match fixtures. SDK PRs that don't pair with a fixture update are still welcome, but cross-impl behavior changes belong in the suite first.

## Tests

`npm test` runs everything. The tests under `test/tpm/` that need a real TPM (`host.e2e.test.ts`, `e2e.http.test.ts`) skip themselves when `/dev/tpmrm0` or tpm2-tools is missing, so CI without a TPM still passes; run them on a machine with a TPM before changing `src/tpm/host.ts` or `src/tpm/commands.ts`. See [Hardware-key path](hardware-key.md#tests).
