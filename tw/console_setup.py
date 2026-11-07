"""Human-only request to activate broker-owned console enrollment."""
from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path

from .admin import human_context_allowed


def _show_code(code):
    # Own remote TTY only, never stdout, logs, files or an Orca pane.
    with open("/dev/tty", "w", encoding="utf-8") as tty:
        tty.write("One-time console enrollment code: " + code + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rp-id", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--config", required=True, type=Path)
    options = parser.parse_args(argv)
    if not human_context_allowed("init") or not os.isatty(0):
        parser.error("Run over SSH from your own device, never in an Orca pane")
    # Guardrails above are not authentication. The broker checks its vault slot.
    config = options.config.absolute()
    if config.name != "config.json" or config.parent.name != "console":
        parser.error("Use BROKER_HOME/console/config.json")
    home = config.parent.parent
    passphrase = getpass.getpass("Vault passphrase (checked by broker, does not unseal): ")
    try:
        from .admin import AdminClient
        with AdminClient(home) as client:
            response = client.call("console_prepare_enrollment", dict(
                passphrase=passphrase, rp_id=options.rp_id, allowed_user=options.user))
        if not response.get("ok"):
            raise ValueError()
        result = response["result"]
        if result["enrollment_required"]:
            _show_code(result["enrollment_code"])
        else:
            print("Console activated. Use your existing passkey at its HTTPS ts.net origin.")
    except Exception:
        raise SystemExit("Console activation refused; check broker and vault authentication") from None
    finally:
        passphrase = ""
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
