/**
 * Deployment constants shared by scripts/deploy.ts and the Hardhat tests.
 * Policy values are basis points (10 000 = 1.0). The initial policy is a starting point for the
 * crypto-path baseline; evaluation (P7) may tune it — every change is an on-chain transaction.
 */
import { keccak256, toUtf8Bytes } from "ethers";

export const ROLES = {
  DEFAULT_ADMIN: "0x0000000000000000000000000000000000000000000000000000000000000000",
  ADMIN: keccak256(toUtf8Bytes("ADMIN_ROLE")),
  PUBLISHER: keccak256(toUtf8Bytes("PUBLISHER_ROLE")),
  GATEWAY: keccak256(toUtf8Bytes("GATEWAY_ROLE")),
} as const;

export const DEFAULT_POLICY = {
  wSbom: 4000,
  wImg: 4000,
  wRep: 2000,
  tauApprove: 3000,
  tauReject: 6000,
} as const;

export const BASIS = 10_000;
