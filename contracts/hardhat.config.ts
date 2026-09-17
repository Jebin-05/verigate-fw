import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-gas-reporter";
import * as dotenv from "dotenv";
dotenv.config({ path: "../.env" });

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.26",
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "cancun" },
  },
  networks: {
    hardhat: { chainId: 31337 },
    localhost: { url: process.env.RPC_URL ?? "http://127.0.0.1:8545" },
    docker: { url: "http://hardhat:8545", chainId: 31337 },   // inside docker compose network
    arbitrumSepolia: {
      url: process.env.ARB_SEPOLIA_RPC_URL ?? "",
      accounts: process.env.ARB_SEPOLIA_DEPLOYER_KEY ? [process.env.ARB_SEPOLIA_DEPLOYER_KEY] : [],
      chainId: 421614,
    },
  },
  gasReporter: { enabled: process.env.REPORT_GAS === "true", outputFile: "gas-report.txt", noColors: true },
  typechain: { outDir: "typechain-types", target: "ethers-v6" },
};
export default config;
