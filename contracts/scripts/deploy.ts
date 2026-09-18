/**
 * Deploys the five registries in dependency order, wires roles, and records addresses.
 *
 * Idempotent: if `deployments/<name>/addresses.json` already points at live code on the same
 * chain, nothing is redeployed. Writes:
 *   - deployments/<name>/addresses.json  (always; <name> = localhost for chainId 31337)
 *   - ../.env                            (chainId 31337 only; updates the *_ADDR lines in place)
 *
 * Gateway account: on chainId 31337 the node's second unlocked account (Hardhat #1, the same key
 * `.env.example` ships as GATEWAY_PRIVATE_KEY); elsewhere `GATEWAY_ADDRESS` or the deployer.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { ethers, network } from "hardhat";
import { DEFAULT_POLICY, ROLES } from "./defaults";

const CONTRACTS = ["PublisherRegistry", "ModelRegistry", "FirmwareRegistry", "PolicyContract", "VerdictRegistry"] as const;
type Name = (typeof CONTRACTS)[number];

interface Deployment {
  chainId: number;
  network: string;
  deployedAt: string;
  deployer: string;
  gateway: string;
  contracts: Record<Name, string>;
  txHashes: Partial<Record<Name, string>>;
}

const ENV_KEYS: Record<Name, string> = {
  PublisherRegistry: "PUBLISHER_REGISTRY_ADDR",
  ModelRegistry: "MODEL_REGISTRY_ADDR",
  FirmwareRegistry: "FIRMWARE_REGISTRY_ADDR",
  PolicyContract: "POLICY_CONTRACT_ADDR",
  VerdictRegistry: "VERDICT_REGISTRY_ADDR",
};

function deploymentName(chainId: number): string {
  if (chainId === 31337) return "localhost";
  if (chainId === 421614) return "arbitrumSepolia";
  return `chain-${chainId}`;
}

async function isLive(existing: Deployment | undefined, chainId: number): Promise<boolean> {
  if (!existing || existing.chainId !== chainId) return false;
  for (const name of CONTRACTS) {
    const addr = existing.contracts[name];
    if (!addr || (await ethers.provider.getCode(addr)) === "0x") return false;
  }
  return true;
}

function updateEnvFile(path: string, deployment: Deployment): boolean {
  if (!existsSync(path)) return false;
  let text = readFileSync(path, "utf8");
  for (const name of CONTRACTS) {
    const key = ENV_KEYS[name];
    const line = `${key}=${deployment.contracts[name]}`;
    text = new RegExp(`^${key}=.*$`, "m").test(text)
      ? text.replace(new RegExp(`^${key}=.*$`, "m"), line)
      : text + (text.endsWith("\n") ? "" : "\n") + line + "\n";
  }
  writeFileSync(path, text);
  return true;
}

async function main(): Promise<void> {
  const { chainId: chainIdBig } = await ethers.provider.getNetwork();
  const chainId = Number(chainIdBig);
  const name = deploymentName(chainId);
  const outFile = join(__dirname, "..", "deployments", name, "addresses.json");
  const signers = await ethers.getSigners();
  const deployer = signers[0];
  if (!deployer) throw new Error("no deployer account configured for this network");
  const gateway =
    chainId === 31337 && signers[1] ? signers[1].address : (process.env.GATEWAY_ADDRESS ?? deployer.address);

  const existing: Deployment | undefined = existsSync(outFile) ? JSON.parse(readFileSync(outFile, "utf8")) : undefined;
  if (await isLive(existing, chainId)) {
    console.log(JSON.stringify({ status: "unchanged", file: outFile, ...existing }, null, 2));
    if (chainId === 31337) updateEnvFile(join(__dirname, "..", "..", ".env"), existing!);
    return;
  }

  const txHashes: Partial<Record<Name, string>> = {};
  const publishers = await ethers.deployContract("PublisherRegistry", [deployer.address]);
  txHashes.PublisherRegistry = publishers.deploymentTransaction()?.hash;
  const models = await ethers.deployContract("ModelRegistry", [deployer.address]);
  txHashes.ModelRegistry = models.deploymentTransaction()?.hash;
  const firmware = await ethers.deployContract("FirmwareRegistry", [deployer.address, await publishers.getAddress()]);
  txHashes.FirmwareRegistry = firmware.deploymentTransaction()?.hash;
  const policy = await ethers.deployContract("PolicyContract", [
    deployer.address,
    DEFAULT_POLICY.wSbom,
    DEFAULT_POLICY.wImg,
    DEFAULT_POLICY.wRep,
    DEFAULT_POLICY.tauApprove,
    DEFAULT_POLICY.tauReject,
  ]);
  txHashes.PolicyContract = policy.deploymentTransaction()?.hash;
  const verdicts = await ethers.deployContract("VerdictRegistry", [deployer.address, await models.getAddress()]);
  txHashes.VerdictRegistry = verdicts.deploymentTransaction()?.hash;

  await (await publishers.grantRole(ROLES.GATEWAY, gateway)).wait();
  await (await verdicts.grantRole(ROLES.GATEWAY, gateway)).wait();

  const deployment: Deployment = {
    chainId,
    network: network.name,
    deployedAt: new Date().toISOString(),
    deployer: deployer.address,
    gateway,
    contracts: {
      PublisherRegistry: await publishers.getAddress(),
      ModelRegistry: await models.getAddress(),
      FirmwareRegistry: await firmware.getAddress(),
      PolicyContract: await policy.getAddress(),
      VerdictRegistry: await verdicts.getAddress(),
    },
    txHashes,
  };
  mkdirSync(dirname(outFile), { recursive: true });
  writeFileSync(outFile, JSON.stringify(deployment, null, 2) + "\n");
  const envUpdated = chainId === 31337 && updateEnvFile(join(__dirname, "..", "..", ".env"), deployment);
  console.log(JSON.stringify({ status: "deployed", file: outFile, envUpdated, ...deployment }, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
