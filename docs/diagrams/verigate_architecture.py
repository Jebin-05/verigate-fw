"""VeriGate-FW architecture diagram. Run: python3 verigate_architecture.py -> PNG + SVG."""

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

# ---------- palette ----------
C = dict(
    bg="#FFFFFF",
    ink="#1F2933",
    muted="#52606D",
    line="#3E4C59",
    pub="#E4E7EB",
    ipfs="#D9F0EC",
    ipfs_b="#1F7A6E",
    l2="#ECE8F8",
    l2_b="#5B3FA6",
    chain="#F7F5FC",
    gw="#F5F7FA",
    gw_b="#9AA5B1",
    s1="#E1EEFB",
    s1_b="#1B5FA8",
    s2="#FFF1DC",
    s2_b="#C7791B",
    pol="#2D3A4A",
    pol_t="#FFFFFF",
    ok="#DDF3E4",
    ok_b="#1E7B45",
    defer="#FFF4CC",
    defer_b="#A0720A",
    rej="#FBE1E1",
    rej_b="#B42323",
    dev="#EEF1F4",
    novel="#C7791B",
)

fig = plt.figure(figsize=(15, 18), dpi=200)
ax = fig.add_axes([0, 0, 1, 1])
ax.set_xlim(0, 122)
ax.set_ylim(0, 152)
ax.axis("off")
fig.patch.set_facecolor(C["bg"])


def box(x0, y0, x1, y1, fc, ec, lw=1.2, r=1.2, z=2, ls="-"):
    p = FancyBboxPatch(
        (x0, y0),
        x1 - x0,
        y1 - y0,
        boxstyle=f"round,pad=0,rounding_size={r}",
        fc=fc,
        ec=ec,
        lw=lw,
        zorder=z,
        linestyle=ls,
    )
    ax.add_patch(p)
    return p


def text(x, y, s, size=9.5, w="normal", color=None, ha="center", va="center", z=5, **kw):
    ax.text(
        x,
        y,
        s,
        fontsize=size,
        fontweight=w,
        color=color or C["ink"],
        ha=ha,
        va=va,
        zorder=z,
        family="DejaVu Sans",
        **kw,
    )


def title_bar(x0, y0, x1, y1, fc, ec, title, sub=None, novel=False):
    box(x0, y0, x1, y1, fc, ec)
    text((x0 + x1) / 2, y1 - 2.2, title, 10.5, "bold", color=ec)
    if novel:
        text(x1 - 1.5, y1 - 2.2, "★", 11, "bold", color=C["novel"], ha="right")
    if sub:
        text((x0 + x1) / 2, y1 - 4.6, sub, 7.8, color=C["muted"])


def arrow(
    pts,
    label=None,
    lpos=None,
    ls="-",
    color=None,
    lw=1.4,
    z=4,
    lsize=7.6,
    lha="center",
    lva="center",
):
    color = color or C["line"]
    for a, b in zip(pts[:-2], pts[1:-1], strict=False):
        ax.add_line(
            Line2D(
                [a[0], b[0]],
                [a[1], b[1]],
                color=color,
                lw=lw,
                ls=ls,
                zorder=z,
                solid_capstyle="round",
            )
        )
    a, b = pts[-2], pts[-1]
    ax.add_patch(
        FancyArrowPatch(
            a, b, arrowstyle="-|>", mutation_scale=13, color=color, lw=lw, ls=ls, zorder=z
        )
    )
    if label:
        lx, ly = lpos
        ax.text(
            lx,
            ly,
            label,
            fontsize=lsize,
            color=C["muted"],
            ha=lha,
            va=lva,
            zorder=6,
            bbox=dict(boxstyle="round,pad=0.25", fc="white", ec="none", alpha=0.95),
            family="DejaVu Sans",
        )


# ---------- title ----------
text(61, 148.5, "VeriGate-FW — Verifiable AI-Gated Firmware Update Architecture", 15, "bold")
text(
    61,
    145.3,
    "Software-only · blockchain (Arbitrum L2) + IPFS · emulated IoT fleet · ★ = novel component",
    9.5,
    color=C["muted"],
)

# ---------- publisher ----------
box(42, 136, 66, 142.5, C["pub"], C["ink"])
text(54, 140.3, "Firmware Publisher", 10.5, "bold")
text(54, 137.9, "Ed25519 key registered in PublisherRegistry", 7.8, color=C["muted"])

# ---------- release builder ----------
box(30, 118, 78, 132, "#FFFFFF", C["ink"])
text(54, 129.8, "Release Builder  (publisher side)", 10.5, "bold")
text(
    54,
    126.4,
    "inputs:  firmware.bin  ·  sbom.json (CycloneDX)  ·  changelog",
    8.2,
    color=C["muted"],
)
text(
    54, 123.3, "manifest = { SHA-256(fw), SHA-256(sbom), version, deviceModel, expiry, CIDs }", 8.2
)
text(
    54,
    120.3,
    "signature = Ed25519.sign(manifest)   —  sign the manifest, never the bare hash",
    8.2,
    w="bold",
    color=C["s1_b"],
)

# ---------- IPFS column ----------
title_bar(3, 62, 22, 132, C["ipfs"], C["ipfs_b"], "IPFS")
text(12.5, 126.5, "content-addressed store\n(Kubo node / local CID store)", 7.6, color=C["muted"])
for i, (f, d) in enumerate(
    [
        ("firmware.bin", "binary image"),
        ("sbom.json", "CycloneDX"),
        ("manifest.json", "signed metadata"),
        ("rationale.json", "LLM explanation"),
    ]
):
    y = 116 - i * 12
    box(5, y - 4, 20, y + 4, "#FFFFFF", C["ipfs_b"], lw=0.9, r=0.8)
    text(12.5, y + 1.3, f, 8.4, "bold", color=C["ipfs_b"])
    text(12.5, y - 1.6, d, 7.2, color=C["muted"])
text(12.5, 66, "every object addressed\nby its CID = hash", 7.2, color=C["muted"], style="italic")

# ---------- L2 column ----------
title_bar(88, 22, 119, 136, C["l2"], C["l2_b"], "Arbitrum L2 (Hardhat local for dev)")


def contract(y0, y1, name, lines, novel=False):
    box(90, y0, 109, y1, C["chain"], C["l2_b"], lw=1.1, r=0.9)
    text(99.5, y1 - 2.1, name, 8.8, "bold", color=C["l2_b"])
    if novel:
        text(108.3, y1 - 2.1, "★", 10, "bold", color=C["novel"], ha="right")
    for i, l in enumerate(lines):
        text(99.5, y1 - 4.6 - i * 2.3, l, 7.1, color=C["muted"])


contract(
    118,
    131,
    "FirmwareRegistry",
    ["manifestHash · signature", "CIDs · version · sbomHash", "expiry · revoked?"],
)
contract(
    95,
    108,
    "PublisherRegistry",
    ["pubkey · status (ACTIVE /", "REVOKED) · rotation history", "reputation score (EWMA)"],
)
contract(
    80,
    93,
    "ModelRegistry",
    ["modelHash = SHA-256(onnx)", "status · successor model", "revoke() ⇒ verdicts STALE"],
    novel=True,
)
contract(
    46,
    59,
    "PolicyContract",
    ["weights w1 w2 w3", "thresholds τ_approve τ_reject", "policy change = audited tx"],
    novel=True,
)
contract(
    26,
    43,
    "VerdictRegistry",
    [
        "modelHash · featureHash · R",
        "verdict · rationaleCID · gwSig",
        "Merkle-batched: 1 tx / N devices",
        "STALE ⇒ gateway re-verifies",
    ],
    novel=True,
)

# ---------- gateway ----------
title_bar(
    26, 40, 82, 110, C["gw"], C["gw_b"], "GATEWAY VERIFIER  (software agent · devices emulated)"
)
# stage 1
box(29, 84, 79, 104, C["s1"], C["s1_b"])
text(
    54,
    101.8,
    "STAGE 1 · CRYPTOGRAPHIC GATE   — deterministic · fail-closed",
    9.5,
    "bold",
    color=C["s1_b"],
)
s1 = [
    ("hash(fw) == manifest.hash", "sig valid under registered key"),
    ("publisher status == ACTIVE", "version  >  device.installedVersion"),
    ("manifest.expiry  >  now", "SHA-256(sbom) == manifest.sbomHash"),
    ("firmware ∉ Revoked", "key ∉ Revoked   ·   model ∉ Revoked"),
]
for i, (l, r) in enumerate(s1):
    y = 97.8 - i * 3.1
    text(31.5, y, "✓ " + l, 7.9, ha="left")
    text(55.5, y, "✓ " + r, 7.9, ha="left")
# stage 2
box(29, 60, 79, 81, C["s2"], C["s2_b"])
text(54, 78.8, "STAGE 2 · AI RISK GATE", 9.5, "bold", color=C["s2_b"])
text(78, 78.8, "★", 11, "bold", color=C["novel"], ha="right")
ai = [
    (
        "SBOM-CVE risk model",
        ["components → OSV.dev", "CVSS · EPSS · KEV", "gradient boosting", "→ r_sbom"],
    ),
    (
        "Image anomaly detector",
        [
            "section entropy · size Δ",
            "string drift · header sanity",
            "Isolation Forest / AE",
            "→ r_img",
        ],
    ),
    (
        "LLM explainer",
        ["SBOM diff + SHAP + changelog", "→ rationale.json", "explain-only —", "NEVER decides"],
    ),
]
for i, (n, ls) in enumerate(ai):
    x0 = 30.5 + i * 16.3
    x1 = x0 + 15.3
    box(x0, 62, x1, 76, "#FFFFFF", C["s2_b"], lw=0.9, r=0.8)
    text((x0 + x1) / 2, 74, n, 8.2, "bold", color=C["s2_b"])
    for j, l in enumerate(ls):
        text(
            (x0 + x1) / 2,
            71 - j * 2.3,
            l,
            7.0,
            color=C["muted"] if j < 3 or i == 2 else C["ink"],
            w="bold" if (j == 3 and i < 2) or (i == 2 and j >= 2) else "normal",
        )
# policy engine
box(29, 44, 79, 57, C["pol"], C["pol"])
text(54, 54.3, "POLICY ENGINE", 9.5, "bold", color=C["pol_t"])
text(54, 50.8, "R  =  w1·r_sbom  +  w2·r_img  +  w3·(1 − reputation)", 8.6, color=C["pol_t"])
text(
    54,
    47.2,
    "weights & thresholds read from PolicyContract  →  APPROVE / DEFER / REJECT",
    7.6,
    color="#C9D2DC",
)
# in-gateway arrows
arrow([(54, 84), (54, 81)])
arrow([(54, 60), (54, 57)])
arrow([(38.2, 62), (38.2, 58.5), (54, 58.5)], lw=1.0)
arrow([(54.5, 62), (54.5, 58.5)], lw=1.0)

# ---------- outcomes ----------
fan_y = 36
ax.add_line(Line2D([54, 54], [44, fan_y], color=C["line"], lw=1.4, zorder=4))
ax.add_line(Line2D([36, 72], [fan_y, fan_y], color=C["line"], lw=1.4, zorder=4))
for x, name, sub, fc, ec in [
    (36, "APPROVE", "push image to device\nA/B slot · signed install receipt", C["ok"], C["ok_b"]),
    (
        54,
        "DEFER",
        "hold · retry · human review\n(chain / OSV unreachable, grey zone)",
        C["defer"],
        C["defer_b"],
    ),
    (72, "REJECT", "block · reputation penalty\nalert dashboard", C["rej"], C["rej_b"]),
]:
    arrow([(x, fan_y), (x, 31)])
    box(x - 8.2, 20, x + 8.2, 31, fc, ec)
    text(x, 28.6, name, 9.5, "bold", color=ec)
    text(x, 24.2, sub, 6.9, color=C["muted"])

# ---------- devices ----------
box(26, 5, 82, 15, C["dev"], C["gw_b"])
text(54, 12.3, "Emulated IoT device fleet  (Python agents)", 9.5, "bold")
text(
    54,
    8.6,
    "persistent NVS: installedVersion (monotonic) · A/B slots · device Ed25519 key · signs install receipt",
    7.6,
    color=C["muted"],
)
arrow([(36, 20), (36, 15)])

# ---------- external arrows ----------
arrow([(54, 136), (54, 132)])
arrow([(30, 125), (22, 125)], "put fw · sbom · manifest  → CIDs", (26, 127.3), lsize=7)
arrow(
    [(78, 125), (90, 125)],
    "register(manifestHash, sig,\nCIDs, version, sbomHash, expiry)",
    (84, 128.8),
    lsize=7,
)
arrow([(90, 119), (85, 119), (85, 110)], "NewRelease event", (85, 114.5), lsize=7, lha="center")
arrow([(22, 94), (29, 94)], "fetch by CID\nrecompute hash", (25.5, 97.3), lsize=6.8)
arrow([(90, 101.5), (79, 101.5)], "key status · reputation", (84.5, 103.2), lsize=6.8)
arrow([(90, 88), (79, 88)], "model status", (84.5, 89.7), lsize=6.8)
arrow([(90, 53.5), (79, 53.5)], "w · τ", (84.5, 55.2), lsize=6.8)
arrow([(79, 47), (85, 47), (85, 36), (90, 36)], "commit verdict\n(batched)", (85, 41.5), lsize=6.8)
arrow([(29, 66), (22, 66)], "rationale → CID", (25.5, 68.3), lsize=6.8)

# ---------- feedback loops (dashed) ----------
fb = C["novel"]
arrow(
    [(109, 86), (113, 86), (113, 34), (109, 34)],
    "revoke(modelHash)\n⇒ all its verdicts STALE\n⇒ re-verify with successor model",
    (99.5, 69.5),
    ls="--",
    color=fb,
    lsize=6.6,
    lha="center",
)
ax.add_line(Line2D([106.5, 113], [69.5, 69.5], color=fb, lw=0.9, ls="--", zorder=4))
arrow(
    [(82, 8), (117, 8), (117, 101), (109, 101)],
    "install receipts  ⇒  reputation ↑",
    (100, 9.9),
    ls="--",
    color=C["ok_b"],
    lsize=6.6,
)
arrow(
    [(72, 20), (72, 17.5), (115, 17.5), (115, 103.5), (109, 103.5)],
    "REJECT  ⇒  reputation ↓",
    (100, 19.4),
    ls="--",
    color=C["rej_b"],
    lsize=6.6,
)

# ---------- legend ----------
ly = 2.2
ax.add_line(Line2D([88, 93], [ly, ly], color=C["line"], lw=1.4))
text(94, ly, "data / control flow", 7.4, ha="left")
ax.add_line(Line2D([104, 109], [ly, ly], color=fb, lw=1.4, ls="--"))
text(110, ly, "feedback loop", 7.4, ha="left")
text(
    54,
    2.2,
    "★ novel: AI risk gate · on-chain policy · attested verdicts · model revocation",
    7.4,
    color=C["novel"],
    w="bold",
)

out = "/home/newuser/Desktop/IOT/diagrams/verigate_architecture"
fig.savefig(out + ".png", dpi=200, facecolor=C["bg"])
fig.savefig(out + ".svg", facecolor=C["bg"])
print("wrote", out + ".png/.svg")
