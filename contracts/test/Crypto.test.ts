import { expect } from "chai";
import { keccak256 } from "ethers";
import { createHash, createPublicKey, verify } from "node:crypto";
import { canonicalJson } from "./helpers/canonical";
import { loadJson, SignedManifestVector } from "./helpers/fixtures";

// DER prefix for an Ed25519 SubjectPublicKeyInfo (RFC 8410), followed by the 32 raw key bytes.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function ed25519Verify(publicKeyHex: string, message: Buffer, signatureHex: string): boolean {
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, "hex")]),
    format: "der",
    type: "spki",
  });
  return verify(null, message, key, Buffer.from(signatureHex, "hex"));
}

describe("Signed manifest golden vector (Python-signed, TypeScript-verified)", () => {
  const vec = loadJson<SignedManifestVector>("crypto/signed_manifest.json");
  const canonical = Buffer.from(canonicalJson(vec.manifest), "utf8");

  it("canonicalises the manifest identically", () => {
    expect(canonical.toString("utf8")).to.equal(vec.canonical);
    expect(createHash("sha256").update(canonical).digest("hex")).to.equal(vec.canonical_sha256);
  });

  it("derives the same keccak256 manifest hash (the on-chain releaseId)", () => {
    expect(keccak256(canonical)).to.equal("0x" + vec.manifest_hash_keccak);
  });

  it("verifies the Ed25519 signature under the publisher key", () => {
    expect(ed25519Verify(vec.public_key_hex, canonical, vec.signature_hex)).to.equal(true);
    expect(vec.public_key).to.equal("ed25519:" + vec.public_key_hex);
  });

  it("rejects a tampered manifest", () => {
    const tampered = Buffer.from(canonicalJson({ ...vec.manifest, version: "1.0.1" }), "utf8");
    expect(ed25519Verify(vec.public_key_hex, tampered, vec.signature_hex)).to.equal(false);
  });

  it("the signed_manifest fixture is the manifest plus its signature", () => {
    const { signature, ...rest } = vec.signed_manifest as { signature: string } & Record<string, unknown>;
    expect(canonicalJson(rest)).to.equal(vec.canonical);
    expect(signature).to.equal("ed25519:" + vec.signature_hex);
  });
});
