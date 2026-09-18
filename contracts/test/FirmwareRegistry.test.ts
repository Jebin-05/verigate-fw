import { loadFixture, time } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { ROLES } from "../scripts/defaults";
import { deployAll } from "./helpers/deploy";
import { hashToBytes32, loadJson, semver, SignedManifestVector } from "./helpers/fixtures";

const vec = loadJson<SignedManifestVector>("crypto/signed_manifest.json");
const DID = vec.manifest.publisherDid;
const PUB_ID = ethers.keccak256(ethers.toUtf8Bytes(DID));
const PUB_KEY = "0x" + vec.public_key_hex;
const MODEL_ID = ethers.keccak256(ethers.toUtf8Bytes(vec.manifest.deviceModel));

/** RegisterInput built from the Python-signed fixture; `manifestHash` doubles as releaseId. */
function inputFromFixture(overrides: Partial<Record<string, unknown>> = {}) {
  const v = semver(vec.manifest.version);
  return {
    deviceModel: vec.manifest.deviceModel,
    major: v.major,
    minor: v.minor,
    patch: v.patch,
    manifestHash: "0x" + vec.manifest_hash_keccak,
    firmwareHash: hashToBytes32(vec.manifest.firmwareHash),
    sbomHash: hashToBytes32(vec.manifest.sbomHash),
    expiry: Math.floor(Date.parse(vec.manifest.expiry) / 1000),
    manifestCid: "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",
    firmwareCid: vec.manifest.cids.firmware,
    sbomCid: vec.manifest.cids.sbom,
    signature: "0x" + vec.signature_hex,
    ...overrides,
  };
}

/** A distinct release (different manifest hash) with the given version triple. */
function later(major: number, minor: number, patch: number, model = vec.manifest.deviceModel) {
  return inputFromFixture({
    major,
    minor,
    patch,
    deviceModel: model,
    manifestHash: ethers.keccak256(ethers.toUtf8Bytes(`${model}:${major}.${minor}.${patch}`)),
  });
}

describe("FirmwareRegistry", () => {
  async function withPublisher() {
    const ctx = await deployAll();
    await ctx.publishers.connect(ctx.publisher).register(DID, PUB_KEY);
    return ctx;
  }
  async function withRelease() {
    const ctx = await withPublisher();
    await ctx.firmware.connect(ctx.publisher).register(inputFromFixture());
    return ctx;
  }

  it("constructor wires roles and the publisher registry", async () => {
    const { firmware, publishers, admin } = await loadFixture(deployAll);
    expect(await firmware.publishers()).to.equal(await publishers.getAddress());
    expect(await firmware.hasRole(ROLES.ADMIN, admin.address)).to.equal(true);
    expect(await firmware.SIGNATURE_LENGTH()).to.equal(64);
  });

  it("packVersion orders like a SemVer tuple", async () => {
    const { firmware } = await loadFixture(deployAll);
    expect(await firmware.packVersion(1, 10, 0)).to.be.gt(await firmware.packVersion(1, 9, 9));
    expect(await firmware.packVersion(2, 0, 0)).to.be.gt(await firmware.packVersion(1, 4294967295, 4294967295));
    expect(await firmware.packVersion(0, 0, 1)).to.be.gt(await firmware.packVersion(0, 0, 0));
    expect(await firmware.packVersion(1, 2, 3)).to.equal((1n << 64n) | (2n << 32n) | 3n);
  });

  describe("register", () => {
    it("stores the fixture release, emits NewRelease and updates lastVersion", async () => {
      const { firmware, publisher } = await loadFixture(withPublisher);
      const input = inputFromFixture();
      const releaseId = await firmware.connect(publisher).register.staticCall(input);
      expect(releaseId).to.equal(input.manifestHash);
      await expect(firmware.connect(publisher).register(input))
        .to.emit(firmware, "NewRelease")
        .withArgs(releaseId, PUB_ID, MODEL_ID, 1, 0, 0, input.manifestHash);
      const r = await firmware.get(releaseId);
      expect(r.publisherId).to.equal(PUB_ID);
      expect(r.deviceModelId).to.equal(MODEL_ID);
      expect(r.deviceModel).to.equal(vec.manifest.deviceModel);
      expect([r.major, r.minor, r.patch]).to.deep.equal([1n, 0n, 0n]);
      expect(r.manifestHash).to.equal(input.manifestHash);
      expect(r.firmwareHash).to.equal(input.firmwareHash);
      expect(r.sbomHash).to.equal(input.sbomHash);
      expect(r.expiry).to.equal(input.expiry);
      expect(r.registeredAt).to.be.gt(0);
      expect(r.revoked).to.equal(false);
      expect(r.manifestCid).to.equal(input.manifestCid);
      expect(r.firmwareCid).to.equal(input.firmwareCid);
      expect(r.sbomCid).to.equal(input.sbomCid);
      expect(r.signature).to.equal(input.signature);
      expect(await firmware.count()).to.equal(1);
      expect(await firmware.releaseIdAt(0)).to.equal(releaseId);
      expect(await firmware.lastVersion(PUB_ID, MODEL_ID)).to.equal(await firmware.packVersion(1, 0, 0));
      expect(await firmware.isRevoked(releaseId)).to.equal(false);
    });

    it("enforces strictly increasing versions per (publisher, deviceModel)", async () => {
      const { firmware, publisher } = await loadFixture(withRelease);
      const packed100 = await firmware.packVersion(1, 0, 0);
      await expect(firmware.connect(publisher).register(later(1, 0, 0)))
        .to.be.revertedWithCustomError(firmware, "VersionNotMonotonic")
        .withArgs(packed100, packed100);
      await expect(firmware.connect(publisher).register(later(0, 9, 9)))
        .to.be.revertedWithCustomError(firmware, "VersionNotMonotonic")
        .withArgs(await firmware.packVersion(0, 9, 9), packed100);
      await firmware.connect(publisher).register(later(1, 0, 1));
      await firmware.connect(publisher).register(later(1, 1, 0));
      await firmware.connect(publisher).register(later(2, 0, 0));
      expect(await firmware.count()).to.equal(4);
      // a different device model has its own counter
      await firmware.connect(publisher).register(later(0, 1, 0, "other-device"));
      expect(await firmware.lastVersion(PUB_ID, ethers.keccak256(ethers.toUtf8Bytes("other-device")))).to.equal(
        await firmware.packVersion(0, 1, 0),
      );
    });

    it("different publishers have independent version counters", async () => {
      const { firmware, publishers, publisher2 } = await loadFixture(withRelease);
      await publishers.connect(publisher2).register("did:verigate:beta", ethers.hexlify(ethers.randomBytes(32)));
      await firmware.connect(publisher2).register(later(0, 0, 1));
      expect(await firmware.count()).to.equal(2);
    });

    it("rejects callers that are not registered publishers", async () => {
      const { firmware, other } = await loadFixture(withPublisher);
      await expect(firmware.connect(other).register(inputFromFixture()))
        .to.be.revertedWithCustomError(firmware, "NotPublisher")
        .withArgs(other.address);
    });

    it("rejects a revoked publisher (stolen-key scenario)", async () => {
      const { firmware, publishers, publisher, admin } = await loadFixture(withRelease);
      await publishers.connect(admin).revoke(PUB_ID);
      // PUBLISHER_ROLE was stripped on revocation → NotPublisher fires first
      await expect(firmware.connect(publisher).register(later(1, 0, 1)))
        .to.be.revertedWithCustomError(firmware, "NotPublisher")
        .withArgs(publisher.address);
    });

    it("rejects an inactive publisher that somehow still holds the role", async () => {
      const { firmware, publishers, publisher, admin } = await loadFixture(withRelease);
      await publishers.connect(admin).revoke(PUB_ID);
      await publishers.connect(admin).grantRole(ROLES.PUBLISHER, publisher.address); // defence-in-depth branch
      await expect(firmware.connect(publisher).register(later(1, 0, 1)))
        .to.be.revertedWithCustomError(firmware, "NotActivePublisher")
        .withArgs(PUB_ID);
    });

    it("rejects malformed inputs: zero manifest hash, wrong signature length, past expiry, duplicate", async () => {
      const { firmware, publisher } = await loadFixture(withRelease);
      await expect(
        firmware.connect(publisher).register({ ...later(1, 0, 1), manifestHash: ethers.ZeroHash }),
      ).to.be.revertedWithCustomError(firmware, "InvalidManifestHash");
      await expect(firmware.connect(publisher).register({ ...later(1, 0, 1), signature: "0x1234" }))
        .to.be.revertedWithCustomError(firmware, "InvalidSignatureLength")
        .withArgs(2);
      const now = await time.latest();
      await expect(firmware.connect(publisher).register({ ...later(1, 0, 1), expiry: now }))
        .to.be.revertedWithCustomError(firmware, "InvalidExpiry")
        .withArgs(now, now + 1);
      await expect(firmware.connect(publisher).register({ ...later(9, 0, 0), manifestHash: inputFromFixture().manifestHash }))
        .to.be.revertedWithCustomError(firmware, "ReleaseExists")
        .withArgs(inputFromFixture().manifestHash);
    });
  });

  describe("revoke", () => {
    it("publisher owner revokes its own release", async () => {
      const { firmware, publisher } = await loadFixture(withRelease);
      const id = inputFromFixture().manifestHash;
      await expect(firmware.connect(publisher).revoke(id)).to.emit(firmware, "ReleaseRevoked").withArgs(id, publisher.address);
      expect(await firmware.isRevoked(id)).to.equal(true);
      expect((await firmware.get(id)).revoked).to.equal(true);
    });

    it("admin revokes any release", async () => {
      const { firmware, admin } = await loadFixture(withRelease);
      const id = inputFromFixture().manifestHash;
      await expect(firmware.connect(admin).revoke(id)).to.emit(firmware, "ReleaseRevoked").withArgs(id, admin.address);
    });

    it("rejects strangers, unknown ids and double revocation", async () => {
      const { firmware, publisher, other } = await loadFixture(withRelease);
      const id = inputFromFixture().manifestHash;
      await expect(firmware.connect(other).revoke(id)).to.be.revertedWithCustomError(firmware, "NotAuthorised").withArgs(other.address);
      const unknown = ethers.keccak256("0x99");
      await expect(firmware.revoke(unknown)).to.be.revertedWithCustomError(firmware, "UnknownRelease").withArgs(unknown);
      await firmware.connect(publisher).revoke(id);
      await expect(firmware.connect(publisher).revoke(id)).to.be.revertedWithCustomError(firmware, "AlreadyRevoked").withArgs(id);
    });

    it("a revoked release does not free its version number", async () => {
      const { firmware, publisher } = await loadFixture(withRelease);
      await firmware.connect(publisher).revoke(inputFromFixture().manifestHash);
      await expect(firmware.connect(publisher).register(later(1, 0, 0))).to.be.revertedWithCustomError(
        firmware,
        "VersionNotMonotonic",
      );
    });
  });

  it("unknown release reads as empty and out-of-range index reverts", async () => {
    const { firmware } = await loadFixture(deployAll);
    const r = await firmware.get(ethers.keccak256("0x01"));
    expect(r.registeredAt).to.equal(0);
    expect(await firmware.isRevoked(ethers.keccak256("0x01"))).to.equal(false);
    await expect(firmware.releaseIdAt(0)).to.be.revertedWithPanic(0x32);
  });
});
