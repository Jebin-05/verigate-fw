import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { ROLES } from "../scripts/defaults";
import { deployAll } from "./helpers/deploy";
import { loadJson } from "./helpers/fixtures";

interface Tree {
  count: number;
  leaves_hex: string[];
  root_hex: string;
  proofs_hex: string[][];
}
const hx = (h: string) => "0x" + h;
const M1 = ethers.sha256(ethers.toUtf8Bytes("sbom_risk_v1.onnx"));
const M2 = ethers.sha256(ethers.toUtf8Bytes("image_anomaly_v1.onnx"));
const M3 = ethers.sha256(ethers.toUtf8Bytes("image_anomaly_v2.onnx"));
const tree5 = loadJson<Tree>("merkle/tree_05.json");
const tree1 = loadJson<Tree>("merkle/tree_01.json");

describe("VerdictRegistry", () => {
  async function withModels() {
    const ctx = await deployAll();
    await ctx.models.register(M1, "sbom_risk_v1");
    await ctx.models.register(M2, "image_anomaly_v1");
    await ctx.models.register(M3, "image_anomaly_v2");
    return ctx;
  }
  async function withBatches() {
    const ctx = await withModels();
    await ctx.verdicts.connect(ctx.gateway).commitBatch(hx(tree5.root_hex), tree5.count, [M1, M2]);
    await ctx.verdicts.connect(ctx.gateway).commitBatch(hx(tree1.root_hex), tree1.count, [M1]);
    await ctx.verdicts.connect(ctx.gateway).commitBatch(ethers.keccak256("0x03"), 3, [M2, M3]);
    return ctx;
  }

  it("constructor wires roles and the model registry", async () => {
    const { verdicts, models, admin } = await loadFixture(deployAll);
    expect(await verdicts.models()).to.equal(await models.getAddress());
    expect(await verdicts.hasRole(ROLES.ADMIN, admin.address)).to.equal(true);
    expect(await verdicts.getRoleAdmin(ROLES.GATEWAY)).to.equal(ROLES.ADMIN);
    expect(await verdicts.MAX_MODELS_PER_BATCH()).to.equal(8);
    expect(await verdicts.batchCount()).to.equal(0);
  });

  describe("commitBatch", () => {
    it("stores root, count, block, gateway and model hashes; emits; returns the id", async () => {
      const { verdicts, gateway } = await loadFixture(withModels);
      const id = await verdicts.connect(gateway).commitBatch.staticCall(hx(tree5.root_hex), 5, [M1, M2]);
      expect(id).to.equal(0);
      const tx = await verdicts.connect(gateway).commitBatch(hx(tree5.root_hex), 5, [M1, M2]);
      const receipt = await tx.wait();
      await expect(tx).to.emit(verdicts, "BatchCommitted").withArgs(0, hx(tree5.root_hex), 5, gateway.address, [M1, M2]);
      const b = await verdicts.getBatch(0);
      expect(b.root).to.equal(hx(tree5.root_hex));
      expect(b.count).to.equal(5);
      expect(b.blockNumber).to.equal(receipt!.blockNumber);
      expect(b.gateway).to.equal(gateway.address);
      expect(b.modelHashes).to.deep.equal([M1, M2]);
      expect(await verdicts.batchCount()).to.equal(1);
      expect(await verdicts.batchesByModel(M1)).to.deep.equal([0n]);
      expect(await verdicts.batchesByModel(M2)).to.deep.equal([0n]);
      expect(await verdicts.batchesByModel(M3)).to.deep.equal([]);
    });

    it("accepts a Stage-1-only batch with no model hashes", async () => {
      const { verdicts, gateway } = await loadFixture(withModels);
      await verdicts.connect(gateway).commitBatch(hx(tree1.root_hex), 1, []);
      expect((await verdicts.getBatch(0)).modelHashes).to.deep.equal([]);
    });

    it("rejects non-gateways, zero root, empty batch, too many models, unknown/revoked models", async () => {
      const { verdicts, models, gateway, other, admin } = await loadFixture(withModels);
      await expect(verdicts.connect(other).commitBatch(hx(tree1.root_hex), 1, []))
        .to.be.revertedWithCustomError(verdicts, "AccessControlUnauthorizedAccount")
        .withArgs(other.address, ROLES.GATEWAY);
      await expect(verdicts.connect(admin).commitBatch(hx(tree1.root_hex), 1, [])).to.be.revertedWithCustomError(
        verdicts,
        "AccessControlUnauthorizedAccount",
      );
      await expect(verdicts.connect(gateway).commitBatch(ethers.ZeroHash, 1, [])).to.be.revertedWithCustomError(
        verdicts,
        "InvalidRoot",
      );
      await expect(verdicts.connect(gateway).commitBatch(hx(tree1.root_hex), 0, [])).to.be.revertedWithCustomError(
        verdicts,
        "EmptyBatch",
      );
      const nine = Array.from({ length: 9 }, () => M1);
      await expect(verdicts.connect(gateway).commitBatch(hx(tree1.root_hex), 1, nine))
        .to.be.revertedWithCustomError(verdicts, "TooManyModels")
        .withArgs(9);
      const unknown = ethers.sha256("0xdead");
      await expect(verdicts.connect(gateway).commitBatch(hx(tree1.root_hex), 1, [M1, unknown]))
        .to.be.revertedWithCustomError(verdicts, "ModelNotActive")
        .withArgs(unknown);
      await models.revoke(M2, M3);
      await expect(verdicts.connect(gateway).commitBatch(hx(tree1.root_hex), 1, [M2]))
        .to.be.revertedWithCustomError(verdicts, "ModelNotActive")
        .withArgs(M2);
    });
  });

  describe("verifyLeaf / verifyRoot", () => {
    it("accepts every Python-generated proof and rejects foreign leaves", async () => {
      const { verdicts } = await loadFixture(withBatches);
      for (let i = 0; i < tree5.count; i++) {
        const proof = tree5.proofs_hex[i].map(hx);
        expect(await verdicts.verifyLeaf(0, hx(tree5.leaves_hex[i]), proof)).to.equal(true);
        expect(await verdicts.verifyRoot(hx(tree5.root_hex), hx(tree5.leaves_hex[i]), proof)).to.equal(true);
        expect(await verdicts.verifyLeaf(1, hx(tree5.leaves_hex[i]), proof)).to.equal(false);
        expect(await verdicts.verifyLeaf(0, ethers.keccak256("0xbeef"), proof)).to.equal(false);
      }
      expect(await verdicts.verifyLeaf(1, hx(tree1.leaves_hex[0]), [])).to.equal(true);
    });

    it("reverts on an unknown batch id (getBatch too)", async () => {
      const { verdicts } = await loadFixture(withBatches);
      await expect(verdicts.verifyLeaf(3, hx(tree1.leaves_hex[0]), [])).to.be.revertedWithCustomError(verdicts, "UnknownBatch").withArgs(3);
      await expect(verdicts.getBatch(3)).to.be.revertedWithCustomError(verdicts, "UnknownBatch").withArgs(3);
    });
  });

  describe("staleByModel", () => {
    it("is empty while the model is ACTIVE or unknown, and lists batches once REVOKED", async () => {
      const { verdicts, models } = await loadFixture(withBatches);
      expect(await verdicts.staleByModel(M2)).to.deep.equal([]);
      expect(await verdicts.staleByModel(ethers.sha256("0x00"))).to.deep.equal([]);
      expect(await verdicts.batchesByModel(M2)).to.deep.equal([0n, 2n]);
      await models.revoke(M2, M3);
      expect(await verdicts.staleByModel(M2)).to.deep.equal([0n, 2n]);
      expect(await verdicts.staleByModel(M1)).to.deep.equal([]);
      expect(await verdicts.staleByModel(M3)).to.deep.equal([]);
    });
  });
});
