import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { DEFAULT_POLICY, ROLES } from "../scripts/defaults";
import { deployAll } from "./helpers/deploy";

describe("PolicyContract", () => {
  it("constructor validates and stores version 1", async () => {
    const { policy, admin } = await loadFixture(deployAll);
    const p = await policy.current();
    expect(p.wSbom).to.equal(DEFAULT_POLICY.wSbom);
    expect(p.wImg).to.equal(DEFAULT_POLICY.wImg);
    expect(p.wRep).to.equal(DEFAULT_POLICY.wRep);
    expect(p.tauApprove).to.equal(DEFAULT_POLICY.tauApprove);
    expect(p.tauReject).to.equal(DEFAULT_POLICY.tauReject);
    expect(p.version).to.equal(1);
    expect(p.changedBy).to.equal(admin.address);
    expect(p.changedAt).to.be.gt(0);
    expect(await policy.version()).to.equal(1);
    expect(await policy.BASIS()).to.equal(10_000);
    expect(await policy.hasRole(ROLES.ADMIN, admin.address)).to.equal(true);
  });

  it("constructor rejects invalid initial policies", async () => {
    const [admin] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("PolicyContract");
    await expect(factory.deploy(admin.address, 5000, 5000, 1, 3000, 6000))
      .to.be.revertedWithCustomError(factory, "WeightsMustSumToBasis")
      .withArgs(10_001);
    await expect(factory.deploy(admin.address, 4000, 4000, 2000, 6000, 6000))
      .to.be.revertedWithCustomError(factory, "ThresholdsOutOfOrder")
      .withArgs(6000, 6000);
    await expect(factory.deploy(admin.address, 4000, 4000, 2000, 3000, 10_001))
      .to.be.revertedWithCustomError(factory, "ThresholdOutOfRange")
      .withArgs(10_001);
  });

  describe("setPolicy", () => {
    it("bumps the version and emits old and new policy", async () => {
      const { policy, admin } = await loadFixture(deployAll);
      const before = await policy.current();
      const tx = await policy.setPolicy(5000, 3000, 2000, 2500, 7000);
      const receipt = await tx.wait();
      const after = await policy.current();
      expect(after.version).to.equal(2);
      expect(after.wSbom).to.equal(5000);
      expect(after.tauApprove).to.equal(2500);
      expect(after.tauReject).to.equal(7000);
      expect(after.changedAt).to.equal(receipt!.blockNumber);
      await expect(tx)
        .to.emit(policy, "PolicyChanged")
        .withArgs(
          2,
          [before.wSbom, before.wImg, before.wRep, before.tauApprove, before.tauReject, before.version, before.changedBy, before.changedAt],
          [5000, 3000, 2000, 2500, 7000, 2, admin.address, receipt!.blockNumber],
          admin.address,
        );
      expect(await policy.version()).to.equal(2);
    });

    it("accepts boundary values (single weight, thresholds 0 and 10000)", async () => {
      const { policy } = await loadFixture(deployAll);
      await policy.setPolicy(10_000, 0, 0, 0, 10_000);
      const p = await policy.current();
      expect(p.wSbom).to.equal(10_000);
      expect(p.tauReject).to.equal(10_000);
    });

    it("rejects weights not summing to 10000", async () => {
      const { policy } = await loadFixture(deployAll);
      await expect(policy.setPolicy(4000, 4000, 1000, 3000, 6000))
        .to.be.revertedWithCustomError(policy, "WeightsMustSumToBasis")
        .withArgs(9000);
      await expect(policy.setPolicy(4000, 4000, 3000, 3000, 6000))
        .to.be.revertedWithCustomError(policy, "WeightsMustSumToBasis")
        .withArgs(11_000);
    });

    it("rejects tauApprove >= tauReject and tauReject > 10000", async () => {
      const { policy } = await loadFixture(deployAll);
      await expect(policy.setPolicy(4000, 4000, 2000, 6000, 6000))
        .to.be.revertedWithCustomError(policy, "ThresholdsOutOfOrder")
        .withArgs(6000, 6000);
      await expect(policy.setPolicy(4000, 4000, 2000, 7000, 6000))
        .to.be.revertedWithCustomError(policy, "ThresholdsOutOfOrder")
        .withArgs(7000, 6000);
      await expect(policy.setPolicy(4000, 4000, 2000, 3000, 10_001))
        .to.be.revertedWithCustomError(policy, "ThresholdOutOfRange")
        .withArgs(10_001);
    });

    it("rejects non-admins (policy tampering is attributable, not possible)", async () => {
      const { policy, other, gateway } = await loadFixture(deployAll);
      await expect(policy.connect(other).setPolicy(4000, 4000, 2000, 1, 2))
        .to.be.revertedWithCustomError(policy, "AccessControlUnauthorizedAccount")
        .withArgs(other.address, ROLES.ADMIN);
      await expect(policy.connect(gateway).setPolicy(4000, 4000, 2000, 1, 2)).to.be.revertedWithCustomError(
        policy,
        "AccessControlUnauthorizedAccount",
      );
      expect(await policy.version()).to.equal(1);
    });
  });
});
