import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { listJson, loadJson } from "./helpers/fixtures";

interface Primitives {
  domain_hex: string;
  leaf: { data_hex: string; leaf_hex: string };
  node: { a_hex: string; b_hex: string; node_hex: string; node_swapped_hex: string };
}
interface Tree {
  count: number;
  data_hex: string[];
  leaves_hex: string[];
  root_hex: string;
  proofs_hex: string[][];
}

const hx = (h: string) => "0x" + h;

describe("MerkleLeaf (Solidity) == verigate.common.merkle (Python)", () => {
  async function deploy() {
    const harness = await ethers.deployContract("MerkleLeafHarness");
    return { harness };
  }

  it("leaf and parent primitives match", async () => {
    const { harness } = await loadFixture(deploy);
    const p = loadJson<Primitives>("merkle/primitives.json");
    expect(await harness.leaf(hx(p.domain_hex), hx(p.leaf.data_hex))).to.equal(hx(p.leaf.leaf_hex));
    expect(await harness.parent(hx(p.node.a_hex), hx(p.node.b_hex))).to.equal(hx(p.node.node_hex));
    expect(await harness.parent(hx(p.node.b_hex), hx(p.node.a_hex))).to.equal(hx(p.node.node_swapped_hex));
  });

  for (const file of listJson("merkle", "tree_")) {
    it(`verifies every proof of ${file}`, async () => {
      const { harness } = await loadFixture(deploy);
      const t = loadJson<Tree>(file);
      const domain = hx(loadJson<Primitives>("merkle/primitives.json").domain_hex);
      for (let i = 0; i < t.count; i++) {
        expect(await harness.leaf(domain, hx(t.data_hex[i]))).to.equal(hx(t.leaves_hex[i]));
        const proof = t.proofs_hex[i].map(hx);
        expect(await harness.verify(hx(t.root_hex), hx(t.leaves_hex[i]), proof)).to.equal(true);
        // a foreign leaf or a truncated proof must fail
        expect(await harness.verify(hx(t.root_hex), ethers.keccak256("0x1234"), proof)).to.equal(false);
        if (proof.length > 0) {
          expect(await harness.verify(hx(t.root_hex), hx(t.leaves_hex[i]), proof.slice(1))).to.equal(false);
        }
      }
    });
  }
});
