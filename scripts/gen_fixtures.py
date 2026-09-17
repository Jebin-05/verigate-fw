"""Regenerate the cross-language golden vectors under ``tests/fixtures/``.

Run ``.venv/bin/python scripts/gen_fixtures.py`` only when a hashing / canonicalisation rule
changes on purpose; commit the result together with the rule change so both the pytest and the
Hardhat suite fail until both sides agree (Manual §4.4).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from verigate.common.canonical import canonical_json
from verigate.common.crypto import KeyPair, sha256_hex
from verigate.common.manifest import Cids, Manifest
from verigate.common.merkle import VERDICT_DOMAIN, MerkleTree, leaf_hash, node_hash

ROOT = Path(__file__).resolve().parents[1] / "tests" / "fixtures"

# A deterministic *test-only* key: seed = sha256("verigate-fixture-key"). Never used for real
# releases; documented in tests/fixtures/crypto/README.md.
FIXTURE_SEED = hashlib.sha256(b"verigate-fixture-key").digest()

CANONICAL_CASES: dict[str, Any] = {
    "01_flat_object": {"b": 1, "a": "x", "c": True, "d": None, "e": False},
    "02_key_order_utf16": {
        "z": 0,
        "a": 1,
        "B": 2,
        "_": 3,
        "1": 4,
        "\u00e9": 5,  # e-acute (BMP)
        "\uff00": 6,  # BMP char above the surrogate range
        "\U0001f600": 7,  # astral char: sorts BEFORE U+FF00 under UTF-16 ordering
        "": 8,
    },
    "03_string_escapes": {
        "quote": 'say "hi"',
        "backslash": "a\\b",
        "controls": "\b\f\n\r\t",
        "low_controls": "\x01\x1f",
        "del_literal": "\x7f",
        "unicode": "h\u00e9llo w\u00f6rld \u2713",
        "emoji": "\U0001f600",
        "slash": "a/b",
    },
    "04_integers": {"zero": 0, "neg": -1, "max": 2**53 - 1, "min": -(2**53 - 1), "arr": [1, -2, 3]},
    "05_nesting": {
        "empty_obj": {},
        "empty_arr": [],
        "nested": {"y": [{"k": [[], {}]}, "s"], "x": {}},
    },
    "06_top_level_array": [{"b": 2, "a": 1}, "s", 0, None, True],
    "07_top_level_string": "just a string with \u00fc and \n",
    "08_manifest_like": {
        "firmwareHash": "sha256:" + "ab" * 32,
        "sbomHash": "sha256:" + "cd" * 32,
        "version": "2.3.0",
        "deviceModel": "acme-lock-v2",
        "expiry": "2027-03-01T00:00:00Z",
        "cids": {"firmware": "bafk" + "a" * 55, "sbom": "bafk" + "b" * 55},
        "publisherDid": "did:verigate:acme",
    },
}


def write(path: Path, payload: Any) -> None:  # noqa: ANN401 — arbitrary JSON
    """Write pretty JSON with a trailing newline (pre-commit's end-of-file-fixer agrees)."""
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n")


def gen_canonical() -> None:
    """One file per case: input, canonical string, canonical hex, sha256 of the bytes."""
    for name, value in CANONICAL_CASES.items():
        canon = canonical_json(value)
        write(
            ROOT / "canonical" / f"{name}.json",
            {
                "input": value,
                "canonical": canon.decode("utf-8"),
                "canonical_hex": canon.hex(),
                "sha256": hashlib.sha256(canon).hexdigest(),
            },
        )


def gen_merkle() -> None:
    """Leaf/node primitives plus whole trees for several sizes (odd sizes exercise promotion)."""
    leaf0 = leaf_hash(VERDICT_DOMAIN, b"record-0")
    leaf1 = leaf_hash(VERDICT_DOMAIN, b"record-1")
    write(
        ROOT / "merkle" / "primitives.json",
        {
            "domain": VERDICT_DOMAIN.decode(),
            "domain_hex": VERDICT_DOMAIN.hex(),
            "leaf": {"data_hex": b"record-0".hex(), "leaf_hex": leaf0.hex()},
            "node": {
                "a_hex": leaf0.hex(),
                "b_hex": leaf1.hex(),
                "node_hex": node_hash(leaf0, leaf1).hex(),
                "node_swapped_hex": node_hash(leaf1, leaf0).hex(),
            },
        },
    )
    for n in (1, 2, 3, 5, 8, 13):
        data = [f"record-{i}".encode() for i in range(n)]
        leaves = [leaf_hash(VERDICT_DOMAIN, d) for d in data]
        tree = MerkleTree.from_leaves(leaves)
        write(
            ROOT / "merkle" / f"tree_{n:02d}.json",
            {
                "count": n,
                "data_hex": [d.hex() for d in data],
                "leaves_hex": [leaf.hex() for leaf in leaves],
                "root_hex": tree.root.hex(),
                "proofs_hex": [[s.hex() for s in tree.proof(i)] for i in range(n)],
            },
        )


def gen_crypto() -> None:
    """A signed manifest under the fixture key, with every intermediate value spelled out."""
    key = KeyPair.from_private(FIXTURE_SEED)
    manifest = Manifest(
        firmwareHash=sha256_hex(b"fixture firmware bytes"),
        sbomHash=sha256_hex(b'{"bomFormat":"CycloneDX"}'),
        version="1.0.0",
        deviceModel="demo-device",
        expiry=datetime(2030, 1, 1, tzinfo=UTC),
        cids=Cids(
            firmware="bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",
            sbom="bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy",
        ),
        publisherDid="did:verigate:fixture",
    )
    signed = manifest.sign(key)
    write(
        ROOT / "crypto" / "signed_manifest.json",
        {
            "private_seed_rule": "sha256('verigate-fixture-key'); test-only, never committed",
            "public_key_hex": key.public.hex(),
            "public_key": key.public_encoded,
            "manifest": manifest.model_dump(mode="json"),
            "canonical": manifest.canonical().decode(),
            "canonical_sha256": hashlib.sha256(manifest.canonical()).hexdigest(),
            "manifest_hash_keccak": manifest.manifest_hash().hex(),
            "signature_hex": key.sign(manifest.canonical()).hex(),
            "signed_manifest": signed.model_dump(mode="json"),
        },
    )


if __name__ == "__main__":
    gen_canonical()
    gen_merkle()
    gen_crypto()
