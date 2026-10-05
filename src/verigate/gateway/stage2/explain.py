"""LLM explainer (P6-05, ADR-0002): a readable rationale for a verdict, never part of ``R``.

Input: the SBOM diff versus the previous release, the Stage-2 scores and their top feature
attributions. Output: strict JSON ``{summary, top_risks[], recommended_action}`` produced by a
model on OpenRouter with a JSON schema as the response format, validated by pydantic, retried
once, and pinned to IPFS — the CID is what the verdict record carries. ``LLM_ENABLED=false``,
a missing API key, an unreachable OpenRouter or a malformed answer all degrade to "no
rationale", never to "no verdict".
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from verigate.common.ipfs import IpfsBackend
from verigate.common.logging import get_logger
from verigate.common.settings import Settings
from verigate.ml.data.sbom import Component, components_of

log = get_logger(__name__)

SYSTEM_PROMPT = (
    "You are a firmware supply-chain security analyst. You are given the outcome of nine "
    "integrity checks on a firmware release and, when they all passed, the software bill of "
    "materials changes compared with the previous release, the risk scores produced by two "
    "deterministic models, and the features that drove those scores. Write a "
    "short, factual rationale for a human reviewer who is not an engineer: plain sentences, no "
    "variable names, no hashes or identifiers (refer to the release by its version), no invented "
    "CVE identifiers. Answer with JSON only."
)

# Feature names as the models know them → the words the reviewer reads (kept in step with the UI).
FEATURE_WORDS: dict[str, str] = {
    "n_components": "number of packages",
    "n_vulnerable_components": "packages with known vulnerabilities",
    "n_cves": "number of known vulnerabilities",
    "max_cvss_x10": "highest severity rating",
    "mean_cvss_x10": "average severity rating",
    "sum_epss_x1e4": "combined chance of exploitation",
    "max_epss_x1e4": "single most exploitable vulnerability",
    "kev_count": "entries on the known-exploited list",
    "n_outdated": "packages behind their newest version",
    "mean_dep_age_days": "age of the packages",
    "size_kb": "file size",
    "entropy_mean_x1000": "randomness of the bytes",
    "entropy_std_x1000": "unevenness of the randomness",
    "entropy_max_x1000": "most random region",
    "high_entropy_chunks_pct": "share that looks packed or encrypted",
    "printable_ratio_x1000": "share of readable text",
    "header_valid": "header well-formed",
    "n_sections": "section count",
    "n_segments": "number of program segments",
    "declared_size_kb": "size declared by the header",
    "appended_kb": "bytes after the declared end",
    "size_delta_kb": "size change since the previous release",
    "entropy_delta_x1000": "randomness change since the previous release",
    "changed_chunks_pct": "share of the file changed since the previous release",
}


# The nine Stage-1 checks as the reviewer reads them (kept in step with the UI's CHECKS).
CHECK_WORDS: dict[str, str] = {
    "firmware_hash": "the firmware file matches its fingerprint",
    "signature": "the release is signed by the publisher's registered key",
    "publisher_active": "the publisher is in good standing",
    "version_monotonic": "the release is newer than the version already on the device",
    "expiry": "the release has not expired",
    "sbom_hash": "the ingredient list matches its fingerprint",
    "registry_record": "the release is still listed by the publisher, not withdrawn",
    "model_active": "the inspection models are current",
    "release_delta": "the file is not the previous trusted release with a few pieces changed",
}


def failure_words(check: str, reason: str | None) -> str:
    """Why ``check`` failed, without hashes or identifiers (kept in step with the UI)."""
    r = reason or ""
    if check == "firmware_hash":
        return "the firmware file that was served is not the file the publisher signed"
    if check == "sbom_hash":
        return "the ingredient list that was served is not the one the publisher signed"
    if check == "signature":
        return "the signature does not verify under the key registered for this publisher"
    if check == "publisher_active":
        if "revoked" in r:
            return "the publisher's key has been revoked"
        return "the publisher is not registered or not in good standing"
    if check == "version_monotonic":
        return "the version is not newer than what the device already runs"
    if check == "expiry":
        return "the release has passed its expiry date, so it may be an old release replayed"
    if check == "registry_record":
        if "revoked" in r:
            return "the publisher has withdrawn this release"
        return "the release record on the blockchain does not match the manifest"
    if check == "model_active":
        return "one of the inspection models has been revoked or is not registered"
    if check == "release_delta":
        if "unavailable" in r:
            return "the previous trusted release could not be fetched for comparison"
        return (
            "the file is the previous trusted release with a few small pieces changed or moved, "
            "which is how a modified build looks, so a person has to review it"
        )
    return "the check failed"


def _plain_value(name: str, raw: Any) -> Any:  # noqa: ANN401 — feature values are JSON scalars
    """Undo the quantisation in the feature name (``_x10`` → ÷10, ``_x1000`` → ÷1000, …)."""
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return raw
    for suffix, scale in (("_x10", 10), ("_x1000", 1000), ("_x1e4", 10_000)):
        if name.endswith(suffix):
            return round(raw / scale, 4)
    return raw


def _readable(top: list[list[Any]], values: dict[str, Any] | None = None) -> list[str]:
    """``[[feature, shap_bp], …]`` → "age of the packages = 412 (pushed the risk down)"."""
    out = []
    for name, weight in top:
        words = FEATURE_WORDS.get(str(name), str(name).replace("_", " "))
        if values and name in values:
            words += f" = {_plain_value(str(name), values[name])}"
        out.append(
            f"{words} ({'pushed the risk up' if float(weight) >= 0 else 'pushed the risk down'})"
        )
    return out


def _risk_level(bp: int) -> str:
    return "low" if bp < 4500 else "moderate" if bp < 7000 else "high"


@dataclass(frozen=True)
class AiReading:
    """What the two risk models said about a release, and where the policy would put that."""

    r_sbom_bp: int
    r_img_bp: int
    top_sbom: list[list[Any]]
    top_img: list[list[Any]]
    sbom_values: dict[str, Any] = field(default_factory=dict)
    img_values: dict[str, Any] = field(default_factory=dict)
    expected_exploited: float | None = None
    cves: int | None = None
    verdict_from_scores: str | None = None
    overall_bp: int | None = None  # both scores combined with the publisher's standing

    def facts(self) -> dict[str, Any]:
        """The prompt's view: levels, scores and the drivers with their values."""
        overall = (
            None
            if self.overall_bp is None
            else f"{_risk_level(self.overall_bp)} ({self.overall_bp / 10_000:.2f} of 1)"
        )
        return {
            "overall risk (both models and the publisher's standing)": overall,
            "ingredient list model (known vulnerabilities)": {
                "risk": f"{_risk_level(self.r_sbom_bp)} ({self.r_sbom_bp / 10_000:.2f} of 1)",
                "known vulnerabilities": self.cves,
                "expected exploited vulnerabilities": self.expected_exploited,
                "why": _readable(self.top_sbom, self.sbom_values),
            },
            "binary structure model (hidden or packed code)": {
                "risk": f"{_risk_level(self.r_img_bp)} ({self.r_img_bp / 10_000:.2f} of 1)",
                "why": _readable(self.top_img, self.img_values),
            },
            "what the scores alone lead to": self.verdict_from_scores,
        }


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

        A full OpenWrt release diff (hundreds of packages) would dominate the prompt's size,
        latency and cost; the counts stay exact.
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
    r_sbom_bp: int | None  # None when the checks stopped the release before the models
    r_img_bp: int | None
    verdict: str
    top_sbom: list[list[Any]]
    top_img: list[list[Any]]
    expected_exploited: float | None = None
    cves: int | None = None
    stopped_at: str | None = None  # the Stage-1 check that failed, if any
    stop_reason: str | None = None
    passed_checks: tuple[str, ...] = ()
    sbom_values: dict[str, Any] = field(default_factory=dict)
    img_values: dict[str, Any] = field(default_factory=dict)
    # A stopped release scored on request afterwards: shown to the writer, never to the gate.
    ai_after_stop: AiReading | None = None
    overall_bp: int | None = None

    def reading(self) -> AiReading:
        """The models' view of a release that reached them."""
        assert self.r_sbom_bp is not None and self.r_img_bp is not None  # noqa: S101
        return AiReading(
            self.r_sbom_bp,
            self.r_img_bp,
            self.top_sbom,
            self.top_img,
            self.sbom_values,
            self.img_values,
            self.expected_exploited,
            self.cves,
            self.verdict,
            self.overall_bp,
        )


@dataclass(frozen=True)
class Explanation:
    """A validated rationale plus where it lives."""

    rationale: Rationale
    cid: str
    model: str
    attempts: int


# The action is the verdict's, not the writer's: the prompt states it and ``explain`` enforces it.
ACTION_FOR_VERDICT: dict[str, str] = {"APPROVE": "install", "DEFER": "review", "REJECT": "block"}


def _stopped_prompt(inp: ExplainInput, action: str) -> str:
    """The user message for a release the checks stopped: no scores exist, so none are given."""
    assert inp.stopped_at is not None  # noqa: S101
    passed = [CHECK_WORDS.get(c, c) for c in inp.passed_checks]
    facts = {
        "release": {"version": inp.version, "device model": inp.device_model},
        "verdict from the deterministic gate": inp.verdict,
        "check that failed": CHECK_WORDS.get(inp.stopped_at, inp.stopped_at),
        "why it failed": failure_words(inp.stopped_at, inp.stop_reason),
        "checks that passed before it": passed,
    }
    if inp.ai_after_stop is None:
        facts["risk models"] = "did not run: the gate stops at the first failed check"
        summary = (
            "3-5 sentences: what failed, what it suggests may have happened, and what it means "
            "for the devices. Do not mention risk scores or vulnerabilities: none were measured"
        )
    else:
        facts["AI risk analysis, run on request after the decision (it did not change it)"] = (
            inp.ai_after_stop.facts()
        )
        summary = (
            "5-7 sentences in two parts. Part 1: what failed, what it suggests may have happened, "
            "and what it means for the devices. Part 2 must start with 'The AI risk analysis' and "
            "say whether the AI judged the release low or high risk and why, naming the factors "
            "that pushed the risk up and down with their values; then say that even so the "
            "failed check decides the outcome"
        )
    return (
        "Facts (JSON):\n"
        + json.dumps(facts, separators=(",", ":"))
        + f"\n\nRespond with a JSON object with keys summary ({summary}), top_risks (up to 5 "
        "plain-English phrases, including the failed check and any factor that raised the AI's "
        f"risk), recommended_action (must be '{action}': it follows the gate's verdict). The "
        "decision was already made by the deterministic gate; explain it for a human."
    )


def build_prompt(inp: ExplainInput) -> str:
    """The user message: structured facts, nothing the model has to guess."""
    action = ACTION_FOR_VERDICT.get(inp.verdict, "review")
    if inp.stopped_at is not None:
        return _stopped_prompt(inp, action)
    facts = {
        "release": {"version": inp.version, "device model": inp.device_model},
        "verdict from the deterministic gate": inp.verdict,
        "all nine integrity checks": "passed",
        "AI risk models": inp.reading().facts(),
        "ingredient list changes versus the previous release": inp.diff.to_json(),
    }
    return (
        "Facts (JSON):\n"
        + json.dumps(facts, separators=(",", ":"))
        + "\n\nRespond with a JSON object with keys summary (3-6 sentences: first whether the AI "
        "judged this release safe or risky and the resulting verdict; then why, naming the "
        "factors that pushed the risk up and those that pushed it down, with their values; then "
        "what it means for the devices), top_risks (up to 5 plain-English phrases for the factors "
        "that raised the risk, such as 'many outdated packages', never field names; empty if "
        f"none), recommended_action (must be '{action}': it follows the gate's verdict). The "
        "decision was already made by the deterministic gate; explain it for a human."
    )


class Explainer:
    """OpenRouter client with a strict schema, one retry and a hard timeout."""

    def __init__(
        self,
        url: str,
        model: str,
        ipfs: IpfsBackend,
        api_key: str = "",
        enabled: bool = True,
        timeout_s: float = 30.0,
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
            timeout=httpx.Timeout(timeout_s, connect=5.0),
            transport=transport,
            headers={"Authorization": f"Bearer {api_key}", "X-Title": "VeriGate-FW"},
        )
        self._cache: dict[str, Explanation | None] = {}
        self._unavailable_until = 0.0

    COOLDOWN_S = 60.0  # after a connection or credential failure, skip (not cache) this long
    # Retrying these cannot help: bad key, no credits, key not allowed to use the model.
    UNAVAILABLE_STATUSES = frozenset({401, 402, 403})

    def forget(self, release_id: str) -> None:
        """Drop the cached answer for ``release_id`` so the next call asks the model again."""
        self._cache.pop(release_id, None)
        self._unavailable_until = 0.0

    def _ask(self, prompt: str) -> Rationale:
        resp = self._http.post(
            f"{self.url}/chat/completions",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "rationale",
                        "strict": True,
                        "schema": RATIONALE_SCHEMA,
                    },
                },
                # Route only to providers that honour the schema, the seed and the token cap.
                "provider": {"require_parameters": True},
                "temperature": 0,
                "seed": self.seed,
                "max_tokens": 400,
            },
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
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
                expected = ACTION_FOR_VERDICT.get(inp.verdict)
                if expected and rationale.recommended_action != expected:
                    # The writer has no authority over the action; keep it equal to the verdict.
                    log.warning(
                        "explain.action_aligned",
                        release_id=inp.release_id,
                        written=rationale.recommended_action,
                        verdict=inp.verdict,
                    )
                    rationale = rationale.model_copy(update={"recommended_action": expected})
            except (httpx.HTTPError, ValidationError, ValueError, KeyError) as exc:
                log.warning(
                    "explain.failed",
                    attempt=attempt,
                    error=str(exc)[:200],
                    release_id=inp.release_id,
                )
                unavailable = isinstance(exc, httpx.ConnectError) or (
                    isinstance(exc, httpx.HTTPStatusError)
                    and exc.response.status_code in self.UNAVAILABLE_STATUSES
                )
                if unavailable:
                    # Offline or refused credentials: do not stall every release on retries.
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
    """The explainer for these settings (``LLM_ENABLED=false`` or no key → a disabled instance)."""
    key = settings.openrouter_api_key.strip()
    if settings.llm_enabled and not key:
        log.warning("explain.disabled_no_key", hint="set OPENROUTER_API_KEY in .env")
    return Explainer(
        settings.openrouter_url,
        settings.llm_model,
        ipfs,
        api_key=key,
        enabled=settings.llm_enabled and bool(key),
        timeout_s=settings.llm_timeout_s,
    )
