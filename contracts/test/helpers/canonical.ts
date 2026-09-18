/**
 * Canonical JSON — the TypeScript twin of `verigate.common.canonical` (Python).
 * Same rules: keys sorted by UTF-16 code units (default JS sort), no whitespace, JSON.stringify
 * string escaping, integers only within the safe range, floats rejected.
 * Verified against `tests/fixtures/canonical/*.json` in Canonical.test.ts.
 */
export function canonicalJson(value: unknown, path = "$"): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isInteger(value)) throw new Error(`${path}: floats are not canonicalisable`);
      if (!Number.isSafeInteger(value)) throw new Error(`${path}: integer exceeds 2**53-1`);
      return Object.is(value, -0) ? "0" : String(value);
    case "bigint":
      throw new Error(`${path}: bigint is not canonicalisable; use a safe integer`);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return "[" + value.map((v, i) => canonicalJson(v, `${path}[${i}]`)).join(",") + "]";
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      return (
        "{" +
        keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k], `${path}.${k}`)}`).join(",") +
        "}"
      );
    }
    default:
      throw new Error(`${path}: type ${typeof value} is not JSON`);
  }
}
