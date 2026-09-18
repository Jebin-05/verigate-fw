/** loadFixture-compatible deployment of the whole contract set with roles wired as deploy.ts does. */
import { ethers } from "hardhat";
import { DEFAULT_POLICY, ROLES } from "../../scripts/defaults";

export async function deployAll() {
  const [admin, gateway, publisher, other, publisher2] = await ethers.getSigners();

  const publishers = await ethers.deployContract("PublisherRegistry", [admin.address]);
  const models = await ethers.deployContract("ModelRegistry", [admin.address]);
  const firmware = await ethers.deployContract("FirmwareRegistry", [admin.address, await publishers.getAddress()]);
  const policy = await ethers.deployContract("PolicyContract", [
    admin.address,
    DEFAULT_POLICY.wSbom,
    DEFAULT_POLICY.wImg,
    DEFAULT_POLICY.wRep,
    DEFAULT_POLICY.tauApprove,
    DEFAULT_POLICY.tauReject,
  ]);
  const verdicts = await ethers.deployContract("VerdictRegistry", [admin.address, await models.getAddress()]);

  await publishers.grantRole(ROLES.GATEWAY, gateway.address);
  await verdicts.grantRole(ROLES.GATEWAY, gateway.address);

  return { admin, gateway, publisher, publisher2, other, publishers, models, firmware, policy, verdicts };
}
