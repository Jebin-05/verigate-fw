"""``make eval EXP=evaluation/configs/<name>.yaml`` — dispatch to ``runners/<experiment>.py``."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import load_config, new_results_dir, write_env  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: run.py evaluation/configs/<experiment>.yaml")
        return 2
    config_path = Path(argv[1])
    config = load_config(config_path)
    experiment = str(config["experiment"])
    module = importlib.import_module(experiment)
    out_dir = new_results_dir(experiment)
    print(f"▶ {experiment} → {out_dir}")
    extra = module.run(config, out_dir)
    write_env(out_dir, config, extra)
    print(f"✔ results in {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
