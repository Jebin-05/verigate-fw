import { expect } from "chai";
import { createHash } from "node:crypto";
import { canonicalJson } from "./helpers/canonical";
import { listJson, loadJson } from "./helpers/fixtures";

interface CanonicalVector {
  input: unknown;
  canonical: string;
  canonical_hex: string;
  sha256: string;
}

describe("Canonical JSON (TypeScript twin of verigate.common.canonical)", () => {
  const files = listJson("canonical");

  it("has the golden vectors", () => {
    expect(files.length).to.be.gte(8);
  });

  for (const file of files) {
    it(`matches ${file}`, () => {
      const vec = loadJson<CanonicalVector>(file);
      const out = canonicalJson(vec.input);
      expect(out).to.equal(vec.canonical);
      const bytes = Buffer.from(out, "utf8");
      expect(bytes.toString("hex")).to.equal(vec.canonical_hex);
      expect(createHash("sha256").update(bytes).digest("hex")).to.equal(vec.sha256);
    });
  }

  it("rejects floats, unsafe integers, bigints and non-JSON", () => {
    expect(() => canonicalJson(1.5)).to.throw("floats");
    expect(() => canonicalJson({ a: 2 ** 53 })).to.throw("exceeds");
    expect(() => canonicalJson(10n)).to.throw("bigint");
    expect(() => canonicalJson(undefined)).to.throw("not JSON");
    expect(() => canonicalJson(() => 1)).to.throw("not JSON");
  });

  it("normalises negative zero and is insertion-order independent", () => {
    expect(canonicalJson(-0)).to.equal("0");
    expect(canonicalJson({ b: 1, a: 2 })).to.equal(canonicalJson({ a: 2, b: 1 }));
  });
});
