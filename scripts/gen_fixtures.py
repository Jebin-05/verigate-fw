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
from verigate.ml.baseline import baseline_bp
from verigate.ml.data.sbom import Component
from verigate.ml.features.sbom_features import (
    FEATURE_NAMES,
    CorpusContext,
    VulnRecord,
    sbom_features,
)

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


SBOM_CASES: dict[str, dict[str, Any]] = {
    "01_clean": {
        "components": [("busybox", "1.36.1-1"), ("dropbear", "2024.85-1")],
        "vulns": {},
    },
    "02_typical": {
        "components": [
            ("openssl", "3.0.1"),
            ("curl", "7.80.0"),
            ("zlib", "1.2.11"),
            ("cjson", "1.7.15"),
        ],
        "vulns": {
            ("openssl", "3.0.1"): [
                ("CVE-2022-0778", 7.5, 0.94, False),
                ("CVE-2022-1292", 9.8, 0.60, True),
            ],
            ("curl", "7.80.0"): [
                ("CVE-2023-38545", 8.8, 0.22, False),
                ("CVE-2022-0778", 7.5, 0.94, False),
            ],
            ("zlib", "1.2.11"): [("CVE-2018-25032", 7.5, 0.05, None)],
        },
    },
    "03_unknown_scores": {
        "components": [("libfoo", "0.1")],
        "vulns": {("libfoo", "0.1"): [("CVE-2099-0001", None, None, False)]},
    },
}
SBOM_CONTEXT = {
    "as_of": "2025-09-18",
    "latest_version": {
        "openssl": "3.0.14",
        "curl": "8.9.1",
        "zlib": "1.2.11",
        "cjson": "1.7.18",
        "busybox": "1.36.1-1",
    },
    "first_seen": {
        "openssl@3.0.1": "2022-01-15",
        "curl@7.80.0": "2021-11-10",
        "zlib@1.2.11": "2017-01-15",
        "busybox@1.36.1-1": "2023-05-18",
    },
}


def gen_sbom_features() -> None:
    """Feature vectors + baseline scores for hand-written vulnerability scenarios (no network)."""
    from datetime import date  # noqa: PLC0415

    context = CorpusContext(
        as_of=date.fromisoformat(SBOM_CONTEXT["as_of"]),
        latest_version=SBOM_CONTEXT["latest_version"],
        first_seen={
            (k.split("@")[0], k.split("@")[1]): date.fromisoformat(v)
            for k, v in SBOM_CONTEXT["first_seen"].items()
        },
    )
    for name, case in SBOM_CASES.items():
        components = [Component(n, v) for n, v in case["components"]]
        vulns = {
            Component(n, v): [
                VulnRecord(cve, cvss, epss, kev is True) for cve, cvss, epss, kev in recs
            ]
            for (n, v), recs in case["vulns"].items()
        }
        features = sbom_features(components, vulns, context)
        all_records = [r for recs in vulns.values() for r in recs]
        write(
            ROOT / "features" / f"sbom_{name}.json",
            {
                "context": SBOM_CONTEXT,
                "components": case["components"],
                "vulns": {f"{n}@{v}": recs for (n, v), recs in case["vulns"].items()},
                "feature_names": list(FEATURE_NAMES),
                "features": features,
                "baseline_bp": baseline_bp(all_records),
            },
        )


if __name__ == "__main__":
    gen_canonical()
    gen_merkle()
    gen_crypto()
    gen_sbom_features()
