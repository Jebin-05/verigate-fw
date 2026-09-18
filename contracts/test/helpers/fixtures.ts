/** Loaders for the cross-language golden vectors under ../tests/fixtures (repo root). */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

export const FIXTURES = join(__dirname, "..", "..", "..", "tests", "fixtures");

export function loadJson<T = unknown>(relative: string): T {
  return JSON.parse(readFileSync(join(FIXTURES, relative), "utf8")) as T;
}

export function listJson(dir: string, prefix = ""): string[] {
  return readdirSync(join(FIXTURES, dir))
    .filter((f) => f.endsWith(".json") && f.startsWith(prefix))
    .sort()
    .map((f) => `${dir}/${f}`);
}

export interface SignedManifestVector {
  public_key_hex: string;
  public_key: string;
  manifest: {
    firmwareHash: string;
    sbomHash: string;
    version: string;
    deviceModel: string;
    expiry: string;
    cids: { firmware: string; sbom: string };
    publisherDid: string;
  };
  canonical: string;
  canonical_sha256: string;
  manifest_hash_keccak: string;
  signature_hex: string;
  signed_manifest: Record<string, unknown>;
}

/** "sha256:<hex>" → 0x-prefixed bytes32 */
export function hashToBytes32(prefixed: string): string {
  if (!prefixed.startsWith("sha256:")) throw new Error("expected sha256: prefix");
  return "0x" + prefixed.slice("sha256:".length);
}

export function semver(v: string): { major: number; minor: number; patch: number } {
  const [major, minor, patch] = v.split(".").map((n) => Number(n));
  return { major, minor, patch };
}
