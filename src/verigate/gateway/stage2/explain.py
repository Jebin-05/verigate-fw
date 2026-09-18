"""LLM explainer (P6-05, ADR-0002): a readable rationale for a verdict, never part of ``R``.

Input: the SBOM diff versus the previous release, the Stage-2 scores and their top feature
attributions. Output: strict JSON ``{summary, top_risks[], recommended_action}`` produced by a
local Ollama model with a JSON schema as the response format, validated by pydantic, retried
once, and pinned to IPFS — the CID is what the verdict record carries. ``LLM_ENABLED=false``,
an unreachable Ollama or a malformed answer all degrade to "no rationale", never to "no verdict".
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from verigate.common.ipfs import IpfsBackend
from verigate.common.logging import get_logger
from verigate.common.settings import Settings
from verigate.ml.data.sbom import Component, components_of

log = get_logger(__name__)

SYSTEM_PROMPT = (
    "You are a firmware supply-chain security analyst. You are given the software bill of "
    "materials changes of a firmware release compared with the previous release, the risk scores "
    "produced by two deterministic models, and the features that drove those scores. Write a "
    "short, factual rationale for a human reviewer. Do not invent CVE identifiers. Answer with "
    "JSON only."
)


class Rationale(BaseModel):
    """The explainer's output (Guide §6.3)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    summary: str = Field(min_length=1, max_length=1200)
    top_risks: list[str] = Field(max_length=5)
    recommended_action: Literal["install", "review", "block"]


MAX_DIFF_ITEMS = 8

RATIONALE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "top_risks": {"type": "array", "items": {"type": "string"}, "maxItems": 5},
        "recommended_action": {"type": "string", "enum": ["install", "review", "block"]},
    },
    "required": ["summary", "top_risks", "recommended_action"],
    "additionalProperties": False,
}


@dataclass(frozen=True)
class SbomDiff:
    """Components added / removed / changed versus the previous release."""

    added: tuple[Component, ...]
    removed: tuple[Component, ...]
    changed: tuple[tuple[str, str, str], ...]  # (name, old version, new version)

    def to_json(self, limit: int = MAX_DIFF_ITEMS) -> dict[str, Any]:
        """Compact JSON for the prompt; each list is truncated to ``limit`` entries with a count.

        A 3B model on CPU evaluates prompt tokens at tens per second, so a full OpenWrt release
        diff (hundreds of packages) would blow the timeout; the counts stay exact.
        """

        def cap(items: list[str]) -> list[str]:
            if len(items) <= limit:
                return items
            return [*items[:limit], f"... and {len(items) - limit} more"]

        return {
            "added": cap([f"{c.name}@{c.version}" for c in self.added]),
            "removed": cap([f"{c.name}@{c.version}" for c in self.removed]),
            "changed": cap([f"{n}: {a} -> {b}" for n, a, b in self.changed]),
            "counts": {
                "added": len(self.added),
                "removed": len(self.removed),
                "changed": len(self.changed),
            },
        }


def sbom_diff(current: bytes, previous: bytes | None) -> SbomDiff:
    """Diff two CycloneDX documents by component name (invalid JSON → empty diff)."""

    def parse(raw: bytes | None) -> dict[str, str]:
        if raw is None:
            return {}
        try:
            return {c.name: c.version for c in components_of(json.loads(raw))}
        except (ValueError, TypeError):
            return {}

    now, before = parse(current), parse(previous)
    added = tuple(Component(n, v) for n, v in sorted(now.items()) if n not in before)
    removed = tuple(Component(n, v) for n, v in sorted(before.items()) if n not in now)
    changed = tuple(
        (n, before[n], v) for n, v in sorted(now.items()) if n in before and before[n] != v
    )
    return SbomDiff(added, removed, changed)


@dataclass(frozen=True)
class ExplainInput:
    """Everything the prompt is built from."""

    release_id: str
    version: str
    device_model: str
    diff: SbomDiff
    r_sbom_bp: int
    r_img_bp: int
    verdict: str
    top_sbom: list[list[Any]]
    top_img: list[list[Any]]
    expected_exploited: float | None = None
    cves: int | None = None


@dataclass(frozen=True)
class Explanation:
    """A validated rationale plus where it lives."""

    rationale: Rationale
    cid: str
    model: str
    attempts: int


def build_prompt(inp: ExplainInput) -> str:
    """The user message: structured facts, nothing the model has to guess."""
    facts = {
        "release": {"id": inp.release_id, "version": inp.version, "deviceModel": inp.device_model},
        "verdict_from_deterministic_gate": inp.verdict,
        "scores": {
            "r_sbom": inp.r_sbom_bp / 10_000,
            "r_img": inp.r_img_bp / 10_000,
            "expected_exploited_cves": inp.expected_exploited,
            "known_cves_in_sbom": inp.cves,
        },
        "top_feature_attributions": {"sbom_model": inp.top_sbom, "image_model": inp.top_img},
        "sbom_changes_vs_previous_release": inp.diff.to_json(),
    }
    return (
        "Facts (JSON):\n"
        + json.dumps(facts, separators=(",", ":"))
        + "\n\nRespond with a JSON object with keys summary (2-4 sentences), top_risks (up to 5 "
        "short strings, empty if none), recommended_action (install | review | block). The "
        "decision was already made by the deterministic gate; explain it for a human."
    )


class Explainer:
    """Ollama client with a strict schema, one retry and a hard timeout."""

    def __init__(
        self,
        url: str,
        model: str,
        ipfs: IpfsBackend,
        enabled: bool = True,
        timeout_s: float = 120.0,
        retries: int = 1,
        seed: int = 42,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.url = url.rstrip("/")
        self.model = model
        self.ipfs = ipfs
        self.enabled = enabled
        self.retries = retries
        self.seed = seed
        self._http = httpx.Client(
            timeout=httpx.Timeout(timeout_s, connect=5.0), transport=transport
        )
        self._cache: dict[str, Explanation | None] = {}
        self._unavailable_until = 0.0

    COOLDOWN_S = 60.0  # after a connection failure, skip (not cache) for this long

    def _ask(self, prompt: str) -> Rationale:
        resp = self._http.post(
            f"{self.url}/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "format": RATIONALE_SCHEMA,
                "stream": False,
                "options": {"temperature": 0, "seed": self.seed, "num_predict": 400},
            },
        )
        resp.raise_for_status()
        content = resp.json()["message"]["content"]
        return Rationale.model_validate_json(content)

    def explain(self, inp: ExplainInput) -> Explanation | None:
        """Produce, validate and pin a rationale; ``None`` if disabled or the LLM failed."""
        if not self.enabled:
            return None
        if inp.release_id in self._cache:
            return self._cache[inp.release_id]
        if time.monotonic() < self._unavailable_until:
            log.info("explain.skipped_unavailable", release_id=inp.release_id)
            return None
        prompt = build_prompt(inp)
        result: Explanation | None = None
        attempts = 0
        for attempt in range(1, self.retries + 2):
            attempts = attempt
            try:
                rationale = self._ask(prompt)
            except (httpx.HTTPError, ValidationError, ValueError, KeyError) as exc:
                log.warning(
                    "explain.failed",
                    attempt=attempt,
                    error=str(exc)[:200],
                    release_id=inp.release_id,
                )
                if isinstance(exc, httpx.ConnectError):
                    # Ollama is not running: do not stall every release for two connect timeouts.
                    self._unavailable_until = time.monotonic() + self.COOLDOWN_S
                    return None
                continue
            payload = rationale.model_dump_json(indent=2).encode()
            cid = self.ipfs.put(payload)
            result = Explanation(rationale, cid, self.model, attempt)
            log.info(
                "explain.ok",
                release_id=inp.release_id,
                cid=cid,
                action=rationale.recommended_action,
                attempts=attempt,
            )
            break
        if result is None:
            log.warning("explain.gave_up", release_id=inp.release_id, attempts=attempts)
        self._cache[inp.release_id] = result
        return result


def build_explainer(settings: Settings, ipfs: IpfsBackend) -> Explainer:
    """The explainer for these settings (``LLM_ENABLED=false`` → a disabled instance)."""
    return Explainer(
        settings.ollama_url,
        settings.llm_model,
        ipfs,
        enabled=settings.llm_enabled,
        timeout_s=settings.llm_timeout_s,
    )
