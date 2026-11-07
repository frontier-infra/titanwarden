"""Write static synthetic console previews. No store, config or HTTP server."""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from tw.console import ASSETS, login_page, vault_page


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=False)
    # Relative asset references permit browser inspection of static fixture files.
    def write(name, text):
        text = text.replace('href="/assets/', 'href="assets/').replace('src="/assets/', 'src="assets/')
        text = text.replace('<main>', '<main><p class="notice">Synthetic preview. No live vault data.</p>')
        (options.output / name).write_text(text, encoding="utf-8")
    empty = dict(seal_state="uninitialized", frozen=False, initialized=False,
                 secret_count=0, secrets=[], truncated=False)
    write("empty.html", vault_page(empty, "synthetic-csrf"))
    write("activation.html", login_page("synthetic-csrf", enrollment=False, active=False))
    write("login.html", login_page("synthetic-csrf", enrollment=False))
    write("enrollment.html", login_page("synthetic-csrf", enrollment=True))
    full = dict(seal_state="sealed", frozen=False, initialized=True, secret_count=1, truncated=False,
        secrets=[dict(path="infra/example", **{"class": "sensitive"}, versions=2, placements=1,
                      last_used="2026-10-23T10:00:00Z", dependents=3,
                      rotation_due="2026-11-01T00:00:00+00:00")])
    write("inventory.html", vault_page(full, "synthetic-csrf", listing=True))
    shutil.copytree(ASSETS, options.output / "assets")
    print("Wrote five static synthetic pages and local assets; no live data or server accessed.")


if __name__ == "__main__":
    main()
