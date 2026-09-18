"""OSV record matching: version normalisation, distro epochs/revisions, tags, OpenWrt mapping."""

from __future__ import annotations

import pytest

from verigate.ml.data.sbom import Component
from verigate.ml.vulndb.match import (
    normalise_version,
    parse_version,
    record_affects,
    upstream_component,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1:1.1.3-1", "1.1.3"),
        ("1.36.1-r3", "1.36.1"),
        ("curl-8_4_0", "8.4.0"),
        ("OpenSSL_1_1_1k", "1.1.1k"),
        ("2.90-2+deb12u1", "2.90"),
        ("1_33_1", "1.33.1"),
        ("5.7.0-stable", "5.7.0"),
        ("0", "0"),
    ],
)
def test_normalise_version(raw: str, expected: str) -> None:
    assert normalise_version(raw) == expected


def test_parse_version_orders_and_falls_back() -> None:
    assert parse_version("1.36.1") is not None
    assert parse_version("2022.82") is not None
    assert parse_version("abc") is None
    a, b = parse_version("1:1.1.3-1"), parse_version("1.36.1")
    assert a is not None and b is not None and a[1] < b[1]


def _rec(entries: list[dict[str, object]]) -> dict[str, object]:
    return {"id": "CVE-2000-0001", "affected": entries}


def test_distro_epoch_range_does_not_match_newer_upstream() -> None:
    debian = _rec(
        [
            {
                "package": {"name": "busybox", "ecosystem": "Debian:12"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:1.1.3-1"}]}
                ],
            }
        ]
    )
    assert record_affects(debian, ["busybox"], "1.36.1") is False
    assert record_affects(debian, ["busybox"], "1.1.2") is True


def test_distro_open_range_is_not_trusted_but_upstream_is() -> None:
    open_distro = _rec(
        [
            {
                "package": {"name": "busybox", "ecosystem": "Ubuntu:22.04:LTS"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ]
    )
    assert record_affects(open_distro, ["busybox"], "1.36.1") is False
    open_upstream = _rec(
        [
            {
                "package": {"name": "busybox", "ecosystem": "GitHub Actions"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.30.0"}]}],
            }
        ]
    )
    assert record_affects(open_upstream, ["busybox"], "1.36.1") is True
    assert record_affects(open_upstream, ["busybox"], "1.29.9") is False


def test_versions_list_and_git_ranges() -> None:
    canonical = _rec(
        [
            {
                "ranges": [{"type": "GIT", "events": [{"introduced": "abc"}, {"fixed": "def"}]}],
                "versions": ["curl-8_4_0", "curl-8_3_0"],
            }
        ]
    )
    assert record_affects(canonical, ["curl"], "8.4.0") is True
    assert record_affects(canonical, ["curl"], "8.7.1") is False
    assert record_affects(canonical, ["curl"], "8.3.0") is True


def test_last_affected_and_other_package_names() -> None:
    rec = _rec(
        [
            {
                "package": {"name": "dnsmasq", "ecosystem": "OSS-Fuzz"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "2.70"}, {"last_affected": "2.80"}],
                    }
                ],
            }
        ]
    )
    assert record_affects(rec, ["dnsmasq"], "2.80") is True
    assert record_affects(rec, ["dnsmasq"], "2.81") is False
    assert record_affects(rec, ["dnsmasq"], "2.69") is False
    assert record_affects(rec, ["busybox"], "2.80") is False
    assert record_affects(rec, ["dnsmasq"], "nonsense") is False
    assert record_affects({"id": "x"}, ["dnsmasq"], "2.80") is False


@pytest.mark.parametrize(
    ("component", "names", "version"),
    [
        (Component("libopenssl3", "3.0.13-1"), ["libopenssl3", "openssl"], "3.0.13"),
        (
            Component("libwolfssl5.7.0.99a6b55f", "5.7.0-stable-1"),
            ["libwolfssl5.7.0.99a6b55f", "wolfssl"],
            "5.7.0",
        ),
        (Component("libcurl4", "8.7.1-1"), ["libcurl4", "curl"], "8.7.1"),
        (Component("libc", "1.2.4-4"), ["libc", "musl"], "1.2.4"),
        (
            Component("wpad-basic-wolfssl", "2023-09-08-e5ccbfc6-6"),
            ["wpad-basic-wolfssl", "hostapd"],
            "2023-09-08-e5ccbfc6",
        ),
        (Component("busybox", "1.36.1-1"), ["busybox"], "1.36.1"),
        (Component("libpcap", "1.10.4-1"), ["libpcap", "pcap"], "1.10.4"),
        (Component("dnsmasq", "2.80-16.3"), ["dnsmasq"], "2.80"),
    ],
)
def test_upstream_component(component: Component, names: list[str], version: str) -> None:
    mapped = upstream_component(component)
    assert mapped is not None
    assert mapped == (names, version)


def test_kernel_and_openwrt_internals_are_excluded() -> None:
    assert upstream_component(Component("kernel", "5.15.150-1-abc")) is None
    assert upstream_component(Component("kmod-nls-base", "5.15.150-1")) is None
    assert upstream_component(Component("uci", "2023.08.10~5781664d-1")) is None
