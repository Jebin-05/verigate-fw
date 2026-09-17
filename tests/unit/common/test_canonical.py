"""Canonical JSON: golden vectors, idempotence, and every rejection branch."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from verigate.common.canonical import MAX_SAFE_INT, canonical_json
from verigate.common.errors import CanonicalError

VECTORS = sorted((Path(__file__).resolve().parents[2] / "fixtures" / "canonical").glob("*.json"))


@pytest.mark.parametrize("path", VECTORS, ids=[p.stem for p in VECTORS])
def test_golden_vector(path: Path) -> None:
    vec = json.loads(path.read_text(encoding="utf-8"))
    out = canonical_json(vec["input"])
    assert out.decode("utf-8") == vec["canonical"]
    assert out.hex() == vec["canonical_hex"]


def test_vectors_exist() -> None:
    assert len(VECTORS) >= 8


def test_key_order_is_utf16_not_codepoint() -> None:
    # U+1F600 (astral, surrogate pair D83D DE00) must sort before U+FF00 as JS does.
    out = canonical_json({"＀": 1, "\U0001f600": 2}).decode()
    assert out == '{"\U0001f600":2,"＀":1}'


def test_no_whitespace_and_sorted() -> None:
    assert (
        canonical_json({"b": [1, 2], "a": {"d": None, "c": True}})
        == b'{"a":{"c":true,"d":null},"b":[1,2]}'
    )


@pytest.mark.parametrize(
    ("value", "match"),
    [
        (1.5, "floats"),
        ({"a": 0.0}, "floats"),
        (2**53, "exceeds"),
        (-(2**53), "exceeds"),
        ({1: "x"}, "not a string"),
        ({"a": {1, 2}}, "sets"),
        (b"bytes", "not JSON"),
        (object(), "not JSON"),
        ("\udc80", "not valid Unicode"),
    ],
)
def test_rejections(value: Any, match: str) -> None:
    with pytest.raises(CanonicalError, match=match):
        canonical_json(value)


json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-MAX_SAFE_INT, max_value=MAX_SAFE_INT),
    st.text(),
)
json_values = st.recursive(
    json_scalars,
    lambda children: st.one_of(st.lists(children), st.dictionaries(st.text(), children)),
    max_leaves=25,
)


@given(json_values)
def test_idempotent_and_round_trips(value: Any) -> None:
    once = canonical_json(value)
    parsed = json.loads(once.decode("utf-8"))
    assert canonical_json(parsed) == once
    assert parsed == value


@given(st.dictionaries(st.text(), st.integers(min_value=0, max_value=9)))
def test_key_order_independent_of_insertion(value: dict[str, int]) -> None:
    reordered = dict(reversed(list(value.items())))
    assert canonical_json(value) == canonical_json(reordered)
