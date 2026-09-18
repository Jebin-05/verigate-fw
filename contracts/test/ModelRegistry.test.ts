import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { ROLES } from "../scripts/defaults";
import { deployAll } from "./helpers/deploy";

const H1 = ethers.sha256(ethers.toUtf8Bytes("image_anomaly_v1.onnx"));
const H2 = ethers.sha256(ethers.toUtf8Bytes("image_anomaly_v2.onnx"));
const H3 = ethers.sha256(ethers.toUtf8Bytes("image_anomaly_v3.onnx"));

describe("ModelRegistry", () => {
  async function withModels() {
    const ctx = await deployAll();
    await ctx.models.register(H1, "image_anomaly_v1");
    await ctx.models.register(H2, "image_anomaly_v2");
    return ctx;
  }

  it("constructor grants admin roles", async () => {
    const { models, admin } = await loadFixture(deployAll);
    expect(await models.hasRole(ROLES.DEFAULT_ADMIN, admin.address)).to.equal(true);
    expect(await models.hasRole(ROLES.ADMIN, admin.address)).to.equal(true);
  });

  describe("register", () => {
    it("stores an ACTIVE record and emits", async () => {
      const { models, admin } = await loadFixture(deployAll);
      await expect(models.register(H1, "image_anomaly_v1"))
        .to.emit(models, "ModelRegistered")
        .withArgs(H1, "image_anomaly_v1", admin.address);
      const m = await models.get(H1);
      expect(m.name).to.equal("image_anomaly_v1");
      expect(m.status).to.equal(1n);
      expect(m.successor).to.equal(ethers.ZeroHash);
      expect(m.registeredAt).to.be.gt(0);
      expect(m.revokedAt).to.equal(0);
      expect(await models.isActive(H1)).to.equal(true);
      expect(await models.statusOf(H1)).to.equal(1n);
      expect(await models.revokedAt(H1)).to.equal(0);
      expect(await models.successorOf(H1)).to.equal(ethers.ZeroHash);
    });

    it("rejects zero hash, duplicates and non-admins", async () => {
      const { models, other } = await loadFixture(withModels);
      await expect(models.register(ethers.ZeroHash, "x")).to.be.revertedWithCustomError(models, "InvalidModelHash");
      await expect(models.register(H1, "again")).to.be.revertedWithCustomError(models, "ModelExists").withArgs(H1);
      await expect(models.connect(other).register(H3, "v3"))
        .to.be.revertedWithCustomError(models, "AccessControlUnauthorizedAccount")
        .withArgs(other.address, ROLES.ADMIN);
    });

    it("unknown hashes read as NONE", async () => {
      const { models } = await loadFixture(deployAll);
      expect(await models.statusOf(H3)).to.equal(0n);
      expect(await models.isActive(H3)).to.equal(false);
    });
  });

  describe("revoke", () => {
    it("revokes with a successor and records revokedAt", async () => {
      const { models, admin } = await loadFixture(withModels);
      const tx = await models.revoke(H1, H2);
      const receipt = await tx.wait();
      await expect(tx).to.emit(models, "ModelRevoked").withArgs(H1, H2, receipt!.blockNumber, admin.address);
      expect(await models.statusOf(H1)).to.equal(2n);
      expect(await models.isActive(H1)).to.equal(false);
      expect(await models.revokedAt(H1)).to.equal(receipt!.blockNumber);
      expect(await models.successorOf(H1)).to.equal(H2);
      expect(await models.isActive(H2)).to.equal(true);
    });

    it("revokes without a successor", async () => {
      const { models } = await loadFixture(withModels);
      await models.revoke(H2, ethers.ZeroHash);
      expect(await models.successorOf(H2)).to.equal(ethers.ZeroHash);
      expect(await models.statusOf(H2)).to.equal(2n);
    });

    it("rejects unknown, already-revoked, self/unknown/revoked successors and non-admins", async () => {
      const { models, other } = await loadFixture(withModels);
      await expect(models.revoke(H3, ethers.ZeroHash)).to.be.revertedWithCustomError(models, "UnknownModel").withArgs(H3);
      await expect(models.revoke(H1, H1)).to.be.revertedWithCustomError(models, "InvalidSuccessor").withArgs(H1);
      await expect(models.revoke(H1, H3)).to.be.revertedWithCustomError(models, "InvalidSuccessor").withArgs(H3);
      await models.revoke(H2, ethers.ZeroHash);
      await expect(models.revoke(H1, H2)).to.be.revertedWithCustomError(models, "InvalidSuccessor").withArgs(H2);
      await expect(models.revoke(H2, ethers.ZeroHash)).to.be.revertedWithCustomError(models, "ModelNotActive").withArgs(H2);
      await expect(models.connect(other).revoke(H1, ethers.ZeroHash)).to.be.revertedWithCustomError(
        models,
        "AccessControlUnauthorizedAccount",
      );
    });
  });
});
