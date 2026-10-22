"""Local runner (uses `az login` credentials unless KVSYNC_CLIENT_ID is set).

    python -m kvsync reconcile
    python -m kvsync sync <certificate-name>

Needs SOURCE_VAULT_URI and DEST_VAULTS_JSON in the environment, exactly like the Function App.
"""
import logging
import sys

from .sync import build_context, reconcile, sync_certificate


def main(argv: list) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    logging.getLogger("azure").setLevel(logging.WARNING)
    if not argv or argv[0] not in ("reconcile", "sync"):
        print(__doc__)
        return 2
    ctx = build_context()
    if argv[0] == "reconcile":
        reconcile(ctx, trigger="manual")
    else:
        sync_certificate(argv[1], ctx, trigger="manual")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
