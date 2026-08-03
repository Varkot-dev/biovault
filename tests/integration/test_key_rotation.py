"""Master-key rotation against a live database.

The operational property being verified: rotating the master KEK must preserve
the ability to decrypt existing records while never touching the bulk
ciphertext. That is the entire justification for envelope encryption, so it is
worth proving rather than assuming.
"""

from __future__ import annotations

import base64
import os

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from biovault.crypto.envelope import (
    DecryptionError,
    EncryptedBlob,
    EnvelopeCipher,
    WrappedKey,
)
from biovault.models.tables import DatasetKey, GenomicRecord
from biovault.scripts.rotate_kek import ENV_NEXT_KEK, rotate

pytestmark = [pytest.mark.integration, pytest.mark.security]

DATASET = "ds-broad-cohort-1"


@pytest.fixture
def next_kek(monkeypatch) -> bytes:
    raw = os.urandom(32)
    monkeypatch.setenv(ENV_NEXT_KEK, base64.b64encode(raw).decode())
    return raw


def _read_one(settings) -> tuple[GenomicRecord, DatasetKey]:
    engine = create_engine(settings.database_url(as_owner=True), future=True)
    with Session(engine, future=True) as db:
        record = db.execute(
            select(GenomicRecord).where(GenomicRecord.dataset_id == DATASET)
        ).scalars().first()
        key = db.execute(
            select(DatasetKey).where(DatasetKey.dataset_id == DATASET)
        ).scalar_one()
        db.expunge_all()
    engine.dispose()
    return record, key


def test_dry_run_changes_nothing(live_settings, next_kek) -> None:
    """A dry run must be safe to execute against production."""
    _, before = _read_one(live_settings)

    count = rotate(from_kek_id=live_settings.master_kek_id, to_kek_id="kek-dryrun", dry_run=True)

    _, after = _read_one(live_settings)
    assert count > 0, "expected keys to rotate; test would be vacuous otherwise"
    assert after.wrapped_key == before.wrapped_key
    assert after.kek_id == before.kek_id


def test_rotation_preserves_plaintext_without_touching_ciphertext(
    live_settings, next_kek
) -> None:
    """The core promise of envelope encryption.

    After rotation the same plaintext must be recoverable under the new KEK,
    and the record's ciphertext column must be byte-identical — proving the
    bulk data was never read or rewritten.
    """
    record_before, key_before = _read_one(live_settings)

    old_cipher = EnvelopeCipher(
        master_kek=live_settings.master_kek_bytes(), kek_id=live_settings.master_kek_id
    )
    plaintext_before = old_cipher.decrypt(
        EncryptedBlob.from_storage(record_before.payload_ciphertext),
        wrapped_key=WrappedKey.from_storage(key_before.wrapped_key),
        dataset_id=DATASET,
    )

    rotated = rotate(
        from_kek_id=live_settings.master_kek_id, to_kek_id="kek-rotated", dry_run=False
    )
    assert rotated > 0

    try:
        record_after, key_after = _read_one(live_settings)

        assert record_after.payload_ciphertext == record_before.payload_ciphertext, (
            "bulk ciphertext was modified; rotation should only rewrap keys"
        )
        assert key_after.wrapped_key != key_before.wrapped_key
        assert key_after.kek_id == "kek-rotated"

        new_cipher = EnvelopeCipher(master_kek=next_kek, kek_id="kek-rotated")
        plaintext_after = new_cipher.decrypt(
            EncryptedBlob.from_storage(record_after.payload_ciphertext),
            wrapped_key=WrappedKey.from_storage(key_after.wrapped_key),
            dataset_id=DATASET,
        )
        assert plaintext_after == plaintext_before

        # The retired key must no longer unwrap anything. Asserting the
        # specific DecryptionError matters: a blind `Exception` would also be
        # satisfied by a typo in this test.
        with pytest.raises(DecryptionError):
            old_cipher.unwrap_data_key(WrappedKey.from_storage(key_after.wrapped_key))
    finally:
        _rotate_back(live_settings, from_kek=next_kek, monkeypatch_value=None)


def _rotate_back(settings, *, from_kek: bytes, monkeypatch_value) -> None:
    """Restore the original KEK so the shared database is left as found."""
    os.environ[ENV_NEXT_KEK] = base64.b64encode(settings.master_kek_bytes()).decode()
    current = EnvelopeCipher(master_kek=from_kek, kek_id="kek-rotated")
    incoming = EnvelopeCipher(
        master_kek=settings.master_kek_bytes(), kek_id=settings.master_kek_id
    )

    engine = create_engine(settings.database_url(as_owner=True), future=True)
    with Session(engine, future=True) as db:
        for row in db.execute(
            select(DatasetKey).where(DatasetKey.kek_id == "kek-rotated")
        ).scalars().all():
            rewrapped = current.rewrap_data_key(
                WrappedKey.from_storage(row.wrapped_key), new_cipher=incoming
            )
            row.wrapped_key = rewrapped.to_storage()
            row.kek_id = rewrapped.kek_id
        db.commit()
    engine.dispose()


def test_rotating_a_kek_id_with_no_keys_is_a_no_op(live_settings, next_kek) -> None:
    assert rotate(from_kek_id="kek-does-not-exist", to_kek_id="kek-x", dry_run=False) == 0


def test_identical_source_and_target_is_rejected(live_settings, next_kek) -> None:
    """Guards against a no-op run that would look successful."""
    from biovault.scripts.rotate_kek import main

    with pytest.raises(SystemExit):
        main(["--from", "kek-1", "--to", "kek-1"])


def test_missing_next_kek_is_rejected(live_settings, monkeypatch) -> None:
    monkeypatch.delenv(ENV_NEXT_KEK, raising=False)
    with pytest.raises(SystemExit, match=ENV_NEXT_KEK):
        rotate(from_kek_id="kek-1", to_kek_id="kek-2", dry_run=True)


def test_malformed_next_kek_is_rejected(live_settings, monkeypatch) -> None:
    monkeypatch.setenv(ENV_NEXT_KEK, base64.b64encode(os.urandom(16)).decode())
    with pytest.raises(SystemExit, match="32 bytes"):
        rotate(from_kek_id="kek-1", to_kek_id="kek-2", dry_run=True)
