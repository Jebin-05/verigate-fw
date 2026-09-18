# Demo-device release fixtures

Three consecutive "releases" of the emulated `demo-device` firmware, used by the Stage-1/2
tests, the smoke test, the demo and the attack scripts:

| fixture | `firmware.bin` | `sbom.json` |
|---|---|---|
| v1.0.0 | OpenWrt 22.03.7 `busybox` (mips_24kc, stripped ELF) | ath79/generic 22.03.7 package manifest |
| v1.1.0 | OpenWrt 23.05.3 `busybox` | ath79/generic 23.05.3 manifest |
| v2.0.0 | OpenWrt 24.10.0 `busybox` | ath79/generic 24.10.0 manifest |

The binaries are real OpenWrt builds (BusyBox is GPL-2.0; OpenWrt is GPL-2.0 — see
https://openwrt.org and https://busybox.net) redistributed unmodified for testing. They keep the
Stage-2 image features in the same distribution as the image-anomaly training corpus
(`data/sources.yaml`, `images` section). `scripts/gen_release_fixtures.py` downloads the pinned
`.ipk` files, verifies their SHA-256 and regenerates everything; `MANIFEST.sha256` records the
outputs (`sha256sum -c MANIFEST.sha256`).
