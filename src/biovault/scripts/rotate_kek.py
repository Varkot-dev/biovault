"""Rewrap every dataset key under a new master KEK.

Envelope encryption means rotation touches only the small wrapped data keys —
the bulk genomic ciphertext is never read or rewritten. See
`docs/key-rotation.md` for the full procedure this implements.

Usage:
    BIOVAULT_MASTER_KEK_NEXT=<base64-32-bytes> \\
    python -m biovault.scripts.rotate_kek --from kek-1 --to kek-2 [--dry-run]
"""

from __future__ import annotations

import argparse
import base64
import logging
import os
import sys

from sqlalchemy import select
from sqlalchemy.orm import Session

from biovault.config import get_settings
from biovault.crypto.envelope import AES_256_KEY_BYTES, DecryptionError, EnvelopeCipher, WrappedKey
from biovault.db.session import owner_engine
from biovault.models.tables import DatasetKey

logger = logging.getLogger("rotate_kek")

ENV_NEXT_KEK = "BIOVAULT_MASTER_KEK_NEXT"  # noqa: S105 - env var name, not a secret


def _load_next_kek() -> bytes:
    """Read and validate the incoming master key from the environment."""
    raw = os.environ.get(ENV_NEXT_KEK, "")
    if not raw:
        raise SystemExit(
            f"{ENV_NEXT_KEK} is not set. Generate one with:\n"
            '  python -c "import base64,os; '
            'print(base64.b64encode(os.urandom(32)).decode())"'
        )
    try:
        decoded = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise SystemExit(f"{ENV_NEXT_KEK} must be valid base64") from exc
    if len(decoded) != AES_256_KEY_BYTES:
        raise SystemExit(
            f"{ENV_NEXT_KEK} must decode to {AES_256_KEY_BYTES} bytes; got {len(decoded)}"
        )
    return decoded


def rotate(*, from_kek_id: str, to_kek_id: str, dry_run: bool) -> int:
    """Rewrap all keys currently under `from_kek_id`. Returns the count.

    Runs as the schema owner because rotation legitimately spans all tenants —
    the one operation in the system that does.
    """
    settings = get_settings()
    current = EnvelopeCipher(
        master_kek=settings.master_kek_bytes(), kek_id=from_kek_id
    )
    incoming = EnvelopeCipher(master_kek=_load_next_kek(), kek_id=to_kek_id)

    rotated = 0
    with Session(owner_engine(), future=True) as session:
        rows = session.execute(
            select(DatasetKey).where(DatasetKey.kek_id == from_kek_id)
        ).scalars().all()

        if not rows:
            logger.info("no keys found under %s; nothing to do", from_kek_id)
            return 0

        for row in rows:
            wrapped = WrappedKey.from_storage(row.wrapped_key)
            try:
                rewrapped = current.rewrap_data_key(wrapped, new_cipher=incoming)
            except DecryptionError:
                # Fail the whole run rather than leaving a half-rotated estate,
                # which would make "is anything still on the old key?" unanswerable.
                raise SystemExit(
                    f"cannot unwrap key for dataset {row.dataset_id!r} under "
                    f"{from_kek_id!r}; aborting without changes"
                ) from None

            if not dry_run:
                row.wrapped_key = rewrapped.to_storage()
                row.kek_id = rewrapped.kek_id
            rotated += 1
            logger.info("%s dataset %s", "would rewrap" if dry_run else "rewrapped",
                        row.dataset_id)

        if dry_run:
            session.rollback()
        else:
            session.commit()

    return rotated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from", dest="from_kek_id", required=True)
    parser.add_argument("--to", dest="to_kek_id", required=True)
    parser.add_argument(
        "--dry-run", action="store_true", help="report what would change, then roll back"
    )
    args = parser.parse_args(argv)

    if args.from_kek_id == args.to_kek_id:
        raise SystemExit("--from and --to must differ")

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    count = rotate(
        from_kek_id=args.from_kek_id, to_kek_id=args.to_kek_id, dry_run=args.dry_run
    )
    verb = "would rotate" if args.dry_run else "rotated"
    logger.info("%s %d dataset key(s) from %s to %s",
                verb, count, args.from_kek_id, args.to_kek_id)
    if not args.dry_run and count:
        logger.info(
            "verify with: SELECT kek_id, count(*) FROM dataset_keys GROUP BY kek_id;"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
