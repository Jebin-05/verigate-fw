# Paper draft (P8-02)

`main.tex` — IEEEtran conference draft. Every number cites a directory under
`evaluation/results/` or a model card; the figures are the PDFs written by
`evaluation/figures.py` (`\graphicspath{{../../evaluation/figures/}}`), nothing else.

Build (no TeX on the dev machine — use the container):
```bash
make figures
docker run --rm -v "$PWD":/work -w /work/docs/paper texlive/texlive:latest latexmk -pdf -interaction=nonstopmode main.tex
```
Regenerate the figures before every build so they match the newest results (Manual §12).
