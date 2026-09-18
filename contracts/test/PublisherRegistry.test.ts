import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { ROLES } from "../scripts/defaults";
import { deployAll } from "./helpers/deploy";

const DID = "did:verigate:acme";
const ID = ethers.keccak256(ethers.toUtf8Bytes(DID));
const KEY = ethers.hexlify(ethers.randomBytes(32));
const KEY2 = ethers.hexlify(ethers.randomBytes(32));
const ZERO32 = ethers.ZeroHash;

describe("PublisherRegistry", () => {
  async function registered() {
    const ctx = await deployAll();
    await ctx.publishers.connect(ctx.publisher).register(DID, KEY);
    return ctx;
  }

  describe("constructor", () => {
    it("grants admin roles and makes ADMIN_ROLE the admin of PUBLISHER/GATEWAY roles", async () => {
      const { publishers, admin } = await loadFixture(deployAll);
      expect(await publishers.hasRole(ROLES.DEFAULT_ADMIN, admin.address)).to.equal(true);
      expect(await publishers.hasRole(ROLES.ADMIN, admin.address)).to.equal(true);
      expect(await publishers.getRoleAdmin(ROLES.PUBLISHER)).to.equal(ROLES.ADMIN);
      expect(await publishers.getRoleAdmin(ROLES.GATEWAY)).to.equal(ROLES.ADMIN);
      expect(await publishers.INITIAL_REPUTATION_BP()).to.equal(5000);
      expect(await publishers.BASIS()).to.equal(10_000);
    });
  });

  describe("register", () => {
    it("stores the record, grants PUBLISHER_ROLE and emits", async () => {
      const { publishers, publisher } = await loadFixture(deployAll);
      await expect(publishers.connect(publisher).register(DID, KEY))
        .to.emit(publishers, "PublisherRegistered")
        .withArgs(ID, DID, publisher.address, KEY);
      const p = await publishers.get(ID);
      expect(p.did).to.equal(DID);
      expect(p.owner).to.equal(publisher.address);
      expect(p.pubKey).to.equal(KEY);
      expect(p.status).to.equal(1n); // ACTIVE
      expect(p.reputationBp).to.equal(5000);
      expect(p.keyVersion).to.equal(0);
      expect(p.registeredAt).to.be.gt(0);
      expect(p.revokedAt).to.equal(0);
      expect(await publishers.isActive(ID)).to.equal(true);
      expect(await publishers.idOf(publisher.address)).to.equal(ID);
      expect(await publishers.ownerOf(ID)).to.equal(publisher.address);
      expect(await publishers.publicKeyOf(ID)).to.equal(KEY);
      expect(await publishers.reputationOf(ID)).to.equal(5000);
      expect(await publishers.hasRole(ROLES.PUBLISHER, publisher.address)).to.equal(true);
    });

    it("returns the id via staticCall", async () => {
      const { publishers, publisher } = await loadFixture(deployAll);
      expect(await publishers.connect(publisher).register.staticCall(DID, KEY)).to.equal(ID);
    });

    it("rejects a short DID and a zero key", async () => {
      const { publishers, publisher } = await loadFixture(deployAll);
      await expect(publishers.connect(publisher).register("did:x", KEY)).to.be.revertedWithCustomError(
        publishers,
        "InvalidDid",
      );
      await expect(publishers.connect(publisher).register(DID, ZERO32)).to.be.revertedWithCustomError(
        publishers,
        "InvalidKey",
      );
    });

    it("rejects a duplicate DID and a second publisher per address", async () => {
      const { publishers, publisher, other } = await loadFixture(registered);
      await expect(publishers.connect(other).register(DID, KEY2))
        .to.be.revertedWithCustomError(publishers, "PublisherExists")
        .withArgs(ID);
      await expect(publishers.connect(publisher).register("did:verigate:second", KEY2))
        .to.be.revertedWithCustomError(publishers, "AddressAlreadyPublisher")
        .withArgs(publisher.address);
    });

    it("unknown ids read as NONE / zero", async () => {
      const { publishers, other } = await loadFixture(deployAll);
      expect((await publishers.get(ID)).status).to.equal(0n);
      expect(await publishers.isActive(ID)).to.equal(false);
      expect(await publishers.idOf(other.address)).to.equal(ZERO32);
      expect(await publishers.ownerOf(ID)).to.equal(ethers.ZeroAddress);
      expect(await publishers.publicKeyOf(ID)).to.equal(ZERO32);
    });
  });

  describe("rotateKey", () => {
    it("replaces the key, bumps keyVersion and emits old/new", async () => {
      const { publishers, publisher } = await loadFixture(registered);
      await expect(publishers.connect(publisher).rotateKey(KEY2))
        .to.emit(publishers, "KeyRotated")
        .withArgs(ID, KEY, KEY2, 1);
      expect(await publishers.publicKeyOf(ID)).to.equal(KEY2);
      expect((await publishers.get(ID)).keyVersion).to.equal(1);
    });

    it("rejects zero key, non-publishers and revoked publishers", async () => {
      const { publishers, publisher, other, admin } = await loadFixture(registered);
      await expect(publishers.connect(publisher).rotateKey(ZERO32)).to.be.revertedWithCustomError(
        publishers,
        "InvalidKey",
      );
      await expect(publishers.connect(other).rotateKey(KEY2))
        .to.be.revertedWithCustomError(publishers, "UnknownPublisher")
        .withArgs(ZERO32);
      await publishers.connect(admin).revoke(ID);
      await expect(publishers.connect(publisher).rotateKey(KEY2))
        .to.be.revertedWithCustomError(publishers, "NotActivePublisher")
        .withArgs(ID);
    });
  });

  describe("revoke", () => {
    it("admin revokes: status REVOKED, revokedAt set, PUBLISHER_ROLE stripped", async () => {
      const { publishers, publisher, admin } = await loadFixture(registered);
      await expect(publishers.connect(admin).revoke(ID))
        .to.emit(publishers, "PublisherRevoked")
        .withArgs(ID, admin.address);
      const p = await publishers.get(ID);
      expect(p.status).to.equal(2n);
      expect(p.revokedAt).to.be.gt(0);
      expect(await publishers.isActive(ID)).to.equal(false);
      expect(await publishers.hasRole(ROLES.PUBLISHER, publisher.address)).to.equal(false);
    });

    it("only ADMIN_ROLE may revoke; unknown and already-revoked ids revert", async () => {
      const { publishers, publisher, admin, other } = await loadFixture(registered);
      await expect(publishers.connect(other).revoke(ID))
        .to.be.revertedWithCustomError(publishers, "AccessControlUnauthorizedAccount")
        .withArgs(other.address, ROLES.ADMIN);
      await expect(publishers.connect(publisher).revoke(ID)).to.be.revertedWithCustomError(
        publishers,
        "AccessControlUnauthorizedAccount",
      );
      const unknown = ethers.keccak256(ethers.toUtf8Bytes("did:verigate:nobody"));
      await expect(publishers.connect(admin).revoke(unknown))
        .to.be.revertedWithCustomError(publishers, "UnknownPublisher")
        .withArgs(unknown);
      await publishers.connect(admin).revoke(ID);
      await expect(publishers.connect(admin).revoke(ID))
        .to.be.revertedWithCustomError(publishers, "NotActivePublisher")
        .withArgs(ID);
    });
  });

  describe("setReputation", () => {
    it("gateway updates reputation and emits old/new", async () => {
      const { publishers, gateway } = await loadFixture(registered);
      await expect(publishers.connect(gateway).setReputation(ID, 7250))
        .to.emit(publishers, "ReputationUpdated")
        .withArgs(ID, 5000, 7250, gateway.address);
      expect(await publishers.reputationOf(ID)).to.equal(7250);
      await publishers.connect(gateway).setReputation(ID, 10_000);
      expect(await publishers.reputationOf(ID)).to.equal(10_000);
    });

    it("rejects non-gateways, out-of-range values and unknown publishers", async () => {
      const { publishers, gateway, admin, other } = await loadFixture(registered);
      await expect(publishers.connect(admin).setReputation(ID, 1))
        .to.be.revertedWithCustomError(publishers, "AccessControlUnauthorizedAccount")
        .withArgs(admin.address, ROLES.GATEWAY);
      await expect(publishers.connect(other).setReputation(ID, 1)).to.be.revertedWithCustomError(
        publishers,
        "AccessControlUnauthorizedAccount",
      );
      await expect(publishers.connect(gateway).setReputation(ID, 10_001))
        .to.be.revertedWithCustomError(publishers, "InvalidReputation")
        .withArgs(10_001);
      const unknown = ethers.keccak256(ethers.toUtf8Bytes("did:verigate:nobody"));
      await expect(publishers.connect(gateway).setReputation(unknown, 1))
        .to.be.revertedWithCustomError(publishers, "UnknownPublisher")
        .withArgs(unknown);
    });

    it("still works for a revoked publisher (history keeps accruing)", async () => {
      const { publishers, gateway, admin } = await loadFixture(registered);
      await publishers.connect(admin).revoke(ID);
      await publishers.connect(gateway).setReputation(ID, 100);
      expect(await publishers.reputationOf(ID)).to.equal(100);
    });
  });

  describe("role administration", () => {
    it("ADMIN_ROLE can grant and revoke GATEWAY_ROLE; others cannot", async () => {
      const { publishers, admin, other } = await loadFixture(deployAll);
      await publishers.connect(admin).grantRole(ROLES.GATEWAY, other.address);
      expect(await publishers.hasRole(ROLES.GATEWAY, other.address)).to.equal(true);
      await publishers.connect(admin).revokeRole(ROLES.GATEWAY, other.address);
      expect(await publishers.hasRole(ROLES.GATEWAY, other.address)).to.equal(false);
      await expect(publishers.connect(other).grantRole(ROLES.GATEWAY, other.address)).to.be.revertedWithCustomError(
        publishers,
        "AccessControlUnauthorizedAccount",
      );
    });
  });
});
