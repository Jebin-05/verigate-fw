r"""Canonical JSON: the one serialisation that is signed and hashed.

Rules (a strict subset of RFC 8785 / JCS so that Python and TypeScript agree byte-for-byte):

* object keys sorted by their UTF-16 code units (what ``Array.prototype.sort`` does in JS);
* no whitespace; ``,`` and ``:`` separators only;
* strings escaped exactly like ``JSON.stringify``: ``\"`` ``\\`` ``\b`` ``\f`` ``\n`` ``\r``
  ``\t`` and ``\u00XX`` (lower-case hex) for other control characters; everything else literal
  UTF-8;
* integers only, with ``|n| <= 2**53 - 1`` (JS safe-integer range); **floats are rejected** —
  anything numeric that must be hashed is quantised to an integer first;
* ``True``/``False``/``None`` → ``true``/``false``/``null``.

Golden vectors live in ``tests/fixtures/canonical/*.json`` and are asserted by both the pytest
suite and the Hardhat suite.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from verigate.common.errors import CanonicalError

MAX_SAFE_INT = 2**53 - 1

_SHORT_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

JsonScalar = str | int | bool | None
Json = JsonScalar | Sequence["Json"] | Mapping[str, "Json"]


def _escape(text: str) -> str:
    out: list[str] = ['"']
    for ch in text:
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be")


def _serialise(value: Any, path: str) -> str:  # noqa: ANN401 — recursive over arbitrary JSON
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise CanonicalError(f"{path}: integer {value} exceeds 2**53-1")
        return str(value)
    if isinstance(value, float):
        raise CanonicalError(f"{path}: floats are not canonicalisable; quantise to int first")
    if isinstance(value, str):
        return _escape(value)
    if isinstance(value, Mapping):
        items: list[tuple[str, Any]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"{path}: object key {key!r} is not a string")
            items.append((key, item))
        items.sort(key=lambda kv: _utf16_key(kv[0]))
        body = ",".join(f"{_escape(k)}:{_serialise(v, f'{path}.{k}')}" for k, v in items)
        return "{" + body + "}"
    if isinstance(value, Sequence | set | frozenset) and not isinstance(value, bytes | bytearray):
        if isinstance(value, set | frozenset):
            raise CanonicalError(f"{path}: sets have no order; use a sorted list")
        return "[" + ",".join(_serialise(v, f"{path}[{i}]") for i, v in enumerate(value)) + "]"
    raise CanonicalError(f"{path}: type {type(value).__name__} is not JSON")


def canonical_json(value: Json) -> bytes:
    """Serialise ``value`` to canonical JSON bytes.

    Args:
        value: Plain JSON data (dict / list / str / int / bool / None). Pydantic models must be
            converted with ``model_dump(mode="json")`` first.

    Returns:
        UTF-8 bytes; same input always yields the same bytes.

    Raises:
        CanonicalError: If the value contains a float, a non-string key, an integer outside the
            JS safe range, or a non-JSON type.
    """
    try:
        return _serialise(value, "$").encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogates cannot be represented in UTF-8
        raise CanonicalError(f"string is not valid Unicode: {exc}") from exc
