// Host-side (attester) TPM access through tpm2-tools: provisions a P-256
// signing key and an attestation key (AK) in the TPM, produces TPM2_Certify
// evidence for a relying-party nonce, and signs requests with the TPM key.
//
// Every tool is run with execFile (no shell) against the resource-managed
// device. The private keys never leave the TPM. Both keys are made persistent
// at fixed handles so raw commands (see ./commands.ts) can address them.
//
// A virtual TPM (e.g. Hyper-V vTPM, swtpm) runs this flow end to end but is
// not a tamper-resistant chip: it proves the flow, not physical-attacker
// resistance.

import { execFile } from "node:child_process";
import { createPublicKey, type KeyObject } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { p256JwkFromPoint, type P256Jwk } from "../p256.js";
import type { P256Signer } from "../rfc9421-p256.js";
import {
  TpmCommandError,
  buildCertifyCommand,
  parseCertifyResponse,
} from "./commands.js";
import type { TpmEvidenceBundle } from "./evidence.js";
import {
  ObjectAttributes,
  TPM_ECC_NIST_P256,
  hasObjectAttributes,
  parseTpm2bPublic,
  tpmtSignatureToRaw,
  type TpmEccPublic,
} from "./structures.js";

const execFileAsync = promisify(execFile);

export const DEFAULT_TCTI = "device:/dev/tpmrm0";
export const DEFAULT_AK_HANDLE = 0x81010010;
export const DEFAULT_KEY_HANDLE = 0x81010011;

const KEY_ATTRIBUTES =
  "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign";
const AK_ATTRIBUTES = `${KEY_ATTRIBUTES}|restricted`;

export interface TpmHostOptions {
  /** TCTI string for tpm2-tools. Defaults to the resource-managed device. */
  tcti?: string;
  /** Persistent handle for the attestation key. */
  akHandle?: number;
  /** Persistent handle for the signing key. */
  keyHandle?: number;
  /** Per-tool timeout in milliseconds. Defaults to 30000. */
  timeoutMs?: number;
}

export class TpmToolError extends Error {
  constructor(
    readonly tool: string,
    readonly stderr: string,
  ) {
    super(`${tool} failed: ${stderr.trim() || "no output"}`);
    this.name = "TpmToolError";
  }
}

const hexHandle = (h: number): string => `0x${h.toString(16)}`;

export interface HardwareKeyInfo {
  /** TPM2B_PUBLIC of the signing key, as it appears in evidence. */
  keyPublic: Uint8Array;
  /** The signing key as the JWK to publish in the DID document. */
  jwk: P256Jwk;
  /** The AK's public key as SPKI PEM: what the relying party must pin. */
  akPem: string;
}

export class TpmHost {
  private readonly tcti: string;
  private readonly akHandle: number;
  private readonly keyHandle: number;
  private readonly timeoutMs: number;

  constructor(options: TpmHostOptions = {}) {
    this.tcti = options.tcti ?? DEFAULT_TCTI;
    this.akHandle = options.akHandle ?? DEFAULT_AK_HANDLE;
    this.keyHandle = options.keyHandle ?? DEFAULT_KEY_HANDLE;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    if (this.akHandle === this.keyHandle) {
      throw new RangeError("akHandle and keyHandle must differ");
    }
  }

  private async tool(name: string, args: string[]): Promise<void> {
    try {
      await execFileAsync(name, args, {
        env: { ...process.env, TPM2TOOLS_TCTI: this.tcti },
        timeout: this.timeoutMs,
      });
    } catch (e) {
      const err = e as { stderr?: string; code?: string; message: string };
      if (err.code === "ENOENT") {
        throw new TpmToolError(name, "not installed (apt install tpm2-tools)");
      }
      throw new TpmToolError(name, err.stderr ?? err.message);
    }
  }

  private async inTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
    const dir = await mkdtemp(join(tmpdir(), "a2a-idf-tpm-"));
    try {
      return await fn(dir);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  /** True if a persistent object exists at `handle`. */
  private async exists(handle: number): Promise<boolean> {
    try {
      await this.inTempDir((dir) =>
        this.tool("tpm2_readpublic", ["-c", hexHandle(handle), "-o", join(dir, "p")]),
      );
      return true;
    } catch (e) {
      if (e instanceof TpmToolError && /not installed/.test(e.message)) throw e;
      return false;
    }
  }

  /**
   * Creates the AK and the signing key under a fresh primary and persists
   * them. Throws if either handle is already occupied unless `replace` is
   * set, in which case the existing objects are evicted first.
   */
  async provision(options: { replace?: boolean } = {}): Promise<HardwareKeyInfo> {
    for (const h of [this.akHandle, this.keyHandle]) {
      if (await this.exists(h)) {
        if (!options.replace) {
          throw new Error(
            `persistent handle ${hexHandle(h)} is already in use; pass { replace: true } to overwrite it`,
          );
        }
        await this.tool("tpm2_evictcontrol", ["-C", "o", "-c", hexHandle(h)]);
      }
    }

    await this.inTempDir(async (dir) => {
      const f = (n: string): string => join(dir, n);
      await this.tool("tpm2_createprimary", [
        "-C", "o", "-G", "ecc", "-g", "sha256", "-c", f("primary.ctx"),
      ]);
      const persist = async (
        name: string,
        alg: string,
        attributes: string,
        handle: number,
      ): Promise<void> => {
        await this.tool("tpm2_create", [
          "-C", f("primary.ctx"), "-G", alg, "-a", attributes,
          "-u", f(`${name}.pub`), "-r", f(`${name}.priv`),
        ]);
        await this.tool("tpm2_load", [
          "-C", f("primary.ctx"), "-u", f(`${name}.pub`), "-r", f(`${name}.priv`),
          "-c", f(`${name}.ctx`),
        ]);
        await this.tool("tpm2_evictcontrol", [
          "-C", "o", "-c", f(`${name}.ctx`), hexHandle(handle),
        ]);
      };
      // A restricted key needs an explicit null symmetric field in the template.
      await persist("ak", "ecc256:ecdsa-sha256:null", AK_ATTRIBUTES, this.akHandle);
      await persist("key", "ecc256:ecdsa-sha256:null", KEY_ATTRIBUTES, this.keyHandle);
    });
    return this.describe();
  }

  /** Reads the public parts of the provisioned keys. */
  async describe(): Promise<HardwareKeyInfo> {
    const keyPublic = await this.readPublic(this.keyHandle);
    const key = parseTpm2bPublic(keyPublic);
    assertHardwareP256(key, "signing key");
    const ak = parseTpm2bPublic(await this.readPublic(this.akHandle));
    assertHardwareP256(ak, "attestation key");
    return {
      keyPublic,
      jwk: jwkOf(key),
      akPem: spkiPem(ak),
    };
  }

  private readPublic(handle: number): Promise<Uint8Array> {
    return this.inTempDir(async (dir) => {
      const out = join(dir, "pub");
      await this.tool("tpm2_readpublic", ["-c", hexHandle(handle), "-o", out]);
      return new Uint8Array(await readFile(out));
    });
  }

  /**
   * Runs TPM2_Certify with the AK over the signing key, with `nonce` as the
   * qualifying data, and returns the evidence bundle for the relying party.
   */
  async certify(nonce: Uint8Array): Promise<TpmEvidenceBundle> {
    if (nonce.byteLength === 0) throw new RangeError("nonce must not be empty");
    const command = buildCertifyCommand(this.keyHandle, this.akHandle, nonce);
    const { certInfo, certSignature } = await this.inTempDir(async (dir) => {
      const cmd = join(dir, "cmd.bin");
      const rsp = join(dir, "rsp.bin");
      await writeFile(cmd, command);
      await this.tool("tpm2_send", ["-o", rsp, cmd]);
      return parseCertifyResponse(new Uint8Array(await readFile(rsp)));
    });
    const keyPublic = await this.readPublic(this.keyHandle);
    const ak = parseTpm2bPublic(await this.readPublic(this.akHandle));
    return {
      certInfo,
      certSignature,
      keyPublic,
      akPublic: spkiDer(ak),
    };
  }

  /** Signs with the TPM key (ECDSA/SHA-256) and returns raw r||s (64 bytes). */
  readonly signer: P256Signer = (message) =>
    this.inTempDir(async (dir) => {
      const msg = join(dir, "msg");
      const sig = join(dir, "sig");
      await writeFile(msg, message);
      await this.tool("tpm2_sign", [
        "-c", hexHandle(this.keyHandle), "-g", "sha256", "-s", "ecdsa",
        "-f", "tss", "-o", sig, msg,
      ]);
      return tpmtSignatureToRaw(new Uint8Array(await readFile(sig)));
    });

  /** Evicts the persistent AK and signing key. */
  async release(): Promise<void> {
    for (const h of [this.akHandle, this.keyHandle]) {
      if (await this.exists(h)) {
        await this.tool("tpm2_evictcontrol", ["-C", "o", "-c", hexHandle(h)]);
      }
    }
  }
}

function assertHardwareP256(pub: TpmEccPublic, what: string): void {
  const required =
    ObjectAttributes.fixedTPM | ObjectAttributes.fixedParent | ObjectAttributes.sign;
  if (pub.curveId !== TPM_ECC_NIST_P256 || !hasObjectAttributes(pub.objectAttributes, required)) {
    throw new TpmCommandError(`${what} is not a fixed P-256 signing key`);
  }
}

const publicKeyOf = (pub: TpmEccPublic): KeyObject =>
  createPublicKey({ key: { ...jwkOf(pub) }, format: "jwk" });

function jwkOf(pub: TpmEccPublic): P256Jwk {
  const point = new Uint8Array(65);
  point[0] = 0x04;
  point.set(pub.x, 1 + 32 - pub.x.byteLength);
  point.set(pub.y, 33 + 32 - pub.y.byteLength);
  return p256JwkFromPoint(point);
}

function spkiDer(pub: TpmEccPublic): Uint8Array {
  return new Uint8Array(
    publicKeyOf(pub).export({ format: "der", type: "spki" }),
  );
}

function spkiPem(pub: TpmEccPublic): string {
  return publicKeyOf(pub).export({ format: "pem", type: "spki" }) as string;
}
