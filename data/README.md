`raw/` and `processed/` are git-ignored. Reproduce with `python -m verigate.ml.data fetch` which downloads
open-source firmware releases (OpenWrt, ESPHome, Tasmota — versions pinned in `sources.yaml`), generates SBOMs with
syft, and builds the tampered set with `verigate.ml.data.mutate` (documented mutations, fixed seed).
`MANIFEST.sha256` records the hash of every file so results are reproducible without committing the data.
