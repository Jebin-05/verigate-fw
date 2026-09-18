/**
 * Deployment constants shared by scripts/deploy.ts and the Hardhat tests.
 * Policy values are basis points (10 000 = 1.0). Defaults follow ADR-0008 (measured on the demo
 * fixtures with both Stage-2 models); every later change is an on-chain transaction.
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
  tauApprove: 4500,
  tauReject: 7000,
} as const;

export const BASIS = 10_000;
