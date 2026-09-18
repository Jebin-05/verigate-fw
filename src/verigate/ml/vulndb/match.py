"""Does an OSV record affect *this* upstream version? (client-side range evaluation, P5-01).

OSV's name-only query matches a record when the version falls into *any* ecosystem's ranges,
and distribution ranges carry epochs and package revisions (``1:1.1.3-1``) that make a plain
upstream version look affected. This module re-evaluates each matched record against the
upstream version with normalised version strings, and maps OpenWrt package names/versions to
upstream ones. The rules are deliberately conservative (an open-ended distro range with no fix
event is *not* counted) and are stated in the model card.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from packaging.version import InvalidVersion, Version

from verigate.ml.data.sbom import Component

# OpenWrt package → upstream project name. Anything not listed goes through the generic rules.
ALIASES: dict[str, str] = {
    "libc": "musl",
    "libpthread": "musl",
    "librt": "musl",
    "libgcc": "gcc",
    "libatomic": "gcc",
    "libstdcpp": "gcc",
    "libustream-wolfssl": "ustream-ssl",
    "libustream-openssl": "ustream-ssl",
    "libustream-mbedtls": "ustream-ssl",
    "px5g-wolfssl": "px5g",
    "px5g-mbedtls": "px5g",
    "wpad-basic-wolfssl": "hostapd",
    "wpad-basic-mbedtls": "hostapd",
    "wpad-basic-openssl": "hostapd",
    "wpad-basic": "hostapd",
    "wpad-mini": "hostapd",
    "wpad": "hostapd",
    "hostapd-common": "hostapd",
    "dnsmasq-full": "dnsmasq",
    "busybox": "busybox",
}
EXCLUDED_PREFIXES = ("kernel", "kmod-", "base-files", "ubus", "ubox", "uci", "procd", "netifd")
"""Not matched: the Linux kernel (branch-based fixes are not comparable to distro ranges) and
OpenWrt's own components, which have no upstream OSV entries."""

DISTRO_MARKERS = (
    "Debian",
    "Ubuntu",
    "Alpine",
    "Rocky",
    "AlmaLinux",
    "Mageia",
    "openSUSE",
    "SUSE",
    "Red Hat",
    "Chainguard",
    "Wolfi",
    "Echo",
    "MinimOS",
    "Photon",
    "BellSoft",
)
_TAG_STRIP = re.compile(
    r"^[A-Za-z][A-Za-z0-9]*[-_]"
)  # 'curl-8_4_0' → '8_4_0', 'OpenSSL_1_1_1k' → '1_1_1k'
_VERSION_CORE = re.compile(r"\d+(?:[._]\d+)*[a-z]?")


def upstream_component(component: Component) -> tuple[list[str], str] | None:
    """Candidate upstream names and the upstream version for an OpenWrt package (or ``None``)."""
    name, version = component.name.lower(), component.version
    if name.startswith(EXCLUDED_PREFIXES):
        return None
    candidates: list[str] = [name]
    alias = ALIASES.get(name)
    if alias:
        candidates.append(alias)
    else:
        stripped = name.removeprefix("lib")
        # 'openssl3' → 'openssl', 'wolfssl5.7.0.99a6b55f' → 'wolfssl', 'json-c5' → 'json-c'
        stripped = re.sub(r"\d[\d.a-f]*$", "", stripped) or stripped
        if stripped != name and len(stripped) >= 3:
            candidates.append(stripped)
        if name.startswith("lib") and len(name) > 3:
            candidates.append(name)  # e.g. libpcap is itself the upstream name
    upstream_version = re.sub(r"-\d+(?:\.\d+)*$", "", version)  # strip OpenWrt package revision
    upstream_version = re.sub(r"-(stable|release)$", "", upstream_version)
    return list(dict.fromkeys(candidates)), upstream_version


def normalise_version(text: str) -> str:
    """Strip epoch, distro revision and tag decoration: ``1:1.36.1-r3`` → ``1.36.1``."""
    text = text.strip()
    text = re.sub(r"^\d+:", "", text)  # Debian epoch
    text = _TAG_STRIP.sub("", text) if not text[:1].isdigit() else text  # git tag prefix
    text = text.replace("_", ".")
    text = re.split(r"[-+~]", text, maxsplit=1)[0]  # revision / dfsg / tilde suffixes
    match = _VERSION_CORE.match(text)
    return match.group(0) if match else text


@lru_cache(maxsize=65536)
def parse_version(text: str) -> tuple[Any, ...] | None:
    """Comparable key for a (normalised) version, or ``None`` if it has no digits."""
    norm = normalise_version(text)
    try:
        return ("pep", Version(norm))
    except InvalidVersion:
        parts = [int(p) for p in re.findall(r"\d+", norm)]
        return ("num", tuple(parts)) if parts else None


def _same(a: tuple[Any, ...], b: tuple[Any, ...]) -> bool:
    if a[0] == b[0]:
        return bool(a[1] == b[1])
    return tuple(int(x) for x in re.findall(r"\d+", str(a[1]))) == tuple(
        int(x) for x in re.findall(r"\d+", str(b[1]))
    )


def _less(a: tuple[Any, ...], b: tuple[Any, ...]) -> bool:
    if a[0] == b[0]:
        return bool(a[1] < b[1])
    # mixed schemes: compare the numeric cores
    na = tuple(int(x) for x in re.findall(r"\d+", str(a[1])))
    nb = tuple(int(x) for x in re.findall(r"\d+", str(b[1])))
    return na < nb


def _range_affects(events: list[dict[str, str]], version: tuple[Any, ...], distro: bool) -> bool:
    introduced: tuple[Any, ...] | None = None
    affected = False
    saw_upper = False
    for event in events:
        if "introduced" in event:
            intro = event["introduced"]
            introduced = ("num", (0,)) if intro == "0" else parse_version(intro)
            affected = introduced is not None and not _less(version, introduced)
        elif "fixed" in event and affected:
            saw_upper = True
            fixed = parse_version(event["fixed"])
            if fixed is None or not _less(version, fixed):
                affected = False
            else:
                return True
        elif "last_affected" in event and affected:
            saw_upper = True
            last = parse_version(event["last_affected"])
            if last is not None and (not _less(last, version)):
                return True
            affected = False
    # an open-ended range: trust upstream/advisory data, never a distro's "unfixed" placeholder
    return affected and not saw_upper and not distro


def record_affects(record: dict[str, Any], names: list[str], version: str) -> bool:
    """True iff ``record`` (an OSV vulnerability) affects upstream ``version`` of ``names``."""
    v = parse_version(version)
    if v is None:
        return False
    wanted = {n.lower() for n in names}
    for entry in record.get("affected") or []:
        package = entry.get("package") or {}
        pname = str(package.get("name", "")).lower()
        ecosystem = str(package.get("ecosystem", ""))
        if pname and pname not in wanted:
            continue
        distro = any(marker.lower() in ecosystem.lower() for marker in DISTRO_MARKERS)
        for tag in entry.get("versions") or []:
            key = parse_version(str(tag))
            if key is not None and _same(key, v):
                return True
        for rng in entry.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue  # commit hashes; the versions list above is what OSV resolved them to
            if _range_affects(list(rng.get("events") or []), v, distro):
                return True
    return False
