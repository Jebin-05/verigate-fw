/** Read-only chain access (ADR-0003): the dashboard never holds a private key. */
import { Contract, JsonRpcProvider } from 'ethers';
import { useEffect, useState } from 'react';
import PolicyAbi from './abi/PolicyContract.json';
import VerdictAbi from './abi/VerdictRegistry.json';

export const RPC_URL: string =
  (import.meta.env.VITE_RPC_URL as string | undefined) ?? 'http://localhost:8545';

const provider = new JsonRpcProvider(RPC_URL);

export interface ChainView {
  block: number | null;
  batchCount: number | null;
  policyVersion: number | null;
  error: string | null;
}

/** Poll the chain directly (not through the gateway) so the panel can see the audit trail itself. */
export function useChain(
  contracts: Record<string, string> | undefined,
  intervalMs = 5000,
): ChainView {
  const [view, setView] = useState<ChainView>({
    block: null,
    batchCount: null,
    policyVersion: null,
    error: null,
  });
  useEffect(() => {
    if (!contracts) return;
    let alive = true;
    const verdicts = new Contract(contracts.VerdictRegistry, VerdictAbi, provider);
    const policy = new Contract(contracts.PolicyContract, PolicyAbi, provider);
    const tick = async () => {
      try {
        const [block, count, version] = await Promise.all([
          provider.getBlockNumber(),
          verdicts.batchCount() as Promise<bigint>,
          policy.version() as Promise<bigint>,
        ]);
        if (alive)
          setView({
            block,
            batchCount: Number(count),
            policyVersion: Number(version),
            error: null,
          });
      } catch (err) {
        if (alive) setView((v) => ({ ...v, error: String(err) }));
      }
    };
    void tick();
    const id = setInterval(() => void tick(), intervalMs);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [contracts, intervalMs]);
  return view;
}

/** `VerdictRegistry.verifyLeaf` straight from the chain — the proof check a reviewer can repeat. */
export async function verifyLeafOnChain(
  verdictRegistry: string,
  batchId: number,
  leaf: string,
  proof: string[],
): Promise<boolean> {
  const contract = new Contract(verdictRegistry, VerdictAbi, provider);
  return (await contract.verifyLeaf(batchId, leaf, proof)) as boolean;
}
