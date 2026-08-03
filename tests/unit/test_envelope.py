"""Unit tests for AES-256-GCM envelope encryption.

The negative cases here are the point: authenticated encryption is only
worth using if tampering is actually detected, so most of these tests
corrupt something and assert that decryption fails loudly.
"""

from __future__ import annotations

import base64
import os

import pytest

from biovault.crypto.envelope import (
    AES_256_KEY_BYTES,
    GCM_NONCE_BYTES,
    DecryptionError,
    EnvelopeCipher,
    WrappedKey,
)

MASTER_KEK = os.urandom(AES_256_KEY_BYTES)
OTHER_KEK = os.urandom(AES_256_KEY_BYTES)
DATASET_A = "dataset-aaaa-1111"
DATASET_B = "dataset-bbbb-2222"


@pytest.fixture
def cipher() -> EnvelopeCipher:
    return EnvelopeCipher(master_kek=MASTER_KEK, kek_id="kek-test")


# --- Round trip -------------------------------------------------------------


def test_encrypt_decrypt_round_trip(cipher: EnvelopeCipher) -> None:
    # Arrange
    wrapped = cipher.generate_data_key(DATASET_A)
    plaintext = b"rs334 A>T sickle-cell variant, synthetic"

    # Act
    blob = cipher.encrypt(plaintext, wrapped_key=wrapped, dataset_id=DATASET_A)
    recovered = cipher.decrypt(blob, wrapped_key=wrapped, dataset_id=DATASET_A)

    # Assert
    assert recovered == plaintext


def test_ciphertext_does_not_contain_plaintext(cipher: EnvelopeCipher) -> None:
    wrapped = cipher.generate_data_key(DATASET_A)
    plaintext = b"BRCA1 c.68_69delAG synthetic marker"

    blob = cipher.encrypt(plaintext, wrapped_key=wrapped, dataset_id=DATASET_A)

    assert plaintext not in blob.ciphertext
    assert b"BRCA1" not in blob.ciphertext


def test_each_encryption_uses_a_fresh_nonce(cipher: EnvelopeCipher) -> None:
    """Nonce reuse under the same key is catastrophic for GCM."""
    wrapped = cipher.generate_data_key(DATASET_A)
    plaintext = b"identical plaintext"

    nonces = {
        cipher.encrypt(plaintext, wrapped_key=wrapped, dataset_id=DATASET_A).nonce
        for _ in range(200)
    }

    assert len(nonces) == 200


def test_identical_plaintext_yields_different_ciphertext(cipher: EnvelopeCipher) -> None:
    """Deterministic ciphertext would leak equality between records."""
    wrapped = cipher.generate_data_key(DATASET_A)
    plaintext = b"same input"

    first = cipher.encrypt(plaintext, wrapped_key=wrapped, dataset_id=DATASET_A)
    second = cipher.encrypt(plaintext, wrapped_key=wrapped, dataset_id=DATASET_A)

    assert first.ciphertext != second.ciphertext


# --- Key sizes and shapes ---------------------------------------------------


def test_data_key_is_256_bits(cipher: EnvelopeCipher) -> None:
    wrapped = cipher.generate_data_key(DATASET_A)
    assert len(cipher.unwrap_data_key(wrapped)) == AES_256_KEY_BYTES


def test_nonce_is_96_bits(cipher: EnvelopeCipher) -> None:
    wrapped = cipher.generate_data_key(DATASET_A)
    blob = cipher.encrypt(b"x", wrapped_key=wrapped, dataset_id=DATASET_A)
    assert len(blob.nonce) == GCM_NONCE_BYTES


def test_rejects_master_key_of_wrong_size() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        EnvelopeCipher(master_kek=os.urandom(16), kek_id="kek-short")


def test_wrapped_key_never_exposes_raw_dek(cipher: EnvelopeCipher) -> None:
    """The wrapped form is what gets persisted; it must not be the raw key."""
    wrapped = cipher.generate_data_key(DATASET_A)
    raw = cipher.unwrap_data_key(wrapped)
    assert raw not in wrapped.wrapped_dek


# --- Tamper detection (the reason for AEAD) ---------------------------------


def test_tampered_ciphertext_is_rejected(cipher: EnvelopeCipher) -> None:
    wrapped = cipher.generate_data_key(DATASET_A)
    blob = cipher.encrypt(b"authentic genomics payload", wrapped_key=wrapped, dataset_id=DATASET_A)

    corrupted = bytearray(blob.ciphertext)
    corrupted[0] ^= 0x01
    tampered = blob.model_copy(update={"ciphertext": bytes(corrupted)})

    with pytest.raises(DecryptionError):
        cipher.decrypt(tampered, wrapped_key=wrapped, dataset_id=DATASET_A)


def test_tampered_nonce_is_rejected(cipher: EnvelopeCipher) -> None:
    wrapped = cipher.generate_data_key(DATASET_A)
    blob = cipher.encrypt(b"payload", wrapped_key=wrapped, dataset_id=DATASET_A)

    corrupted = bytearray(blob.nonce)
    corrupted[0] ^= 0xFF
    tampered = blob.model_copy(update={"nonce": bytes(corrupted)})

    with pytest.raises(DecryptionError):
        cipher.decrypt(tampered, wrapped_key=wrapped, dataset_id=DATASET_A)


def test_truncated_ciphertext_is_rejected(cipher: EnvelopeCipher) -> None:
    wrapped = cipher.generate_data_key(DATASET_A)
    blob = cipher.encrypt(b"a reasonably long genomics payload", wrapped_key=wrapped,
                          dataset_id=DATASET_A)

    tampered = blob.model_copy(update={"ciphertext": blob.ciphertext[:-4]})

    with pytest.raises(DecryptionError):
        cipher.decrypt(tampered, wrapped_key=wrapped, dataset_id=DATASET_A)


def test_tampered_wrapped_dek_is_rejected(cipher: EnvelopeCipher) -> None:
    """The DEK is itself wrapped with AEAD, so corrupting it must be caught."""
    wrapped = cipher.generate_data_key(DATASET_A)

    corrupted = bytearray(wrapped.wrapped_dek)
    corrupted[0] ^= 0x01
    bad_key = wrapped.model_copy(update={"wrapped_dek": bytes(corrupted)})

    with pytest.raises(DecryptionError):
        cipher.unwrap_data_key(bad_key)


# --- Cross-dataset and cross-key isolation ----------------------------------


def test_ciphertext_moved_to_another_dataset_fails(cipher: EnvelopeCipher) -> None:
    """Dataset ID is bound as AAD, so a relocated blob must not decrypt.

    Defends against an attacker with database write access swapping encrypted
    records between datasets to read another lab's data through their own
    authorized decryption path.
    """
    wrapped = cipher.generate_data_key(DATASET_A)
    blob = cipher.encrypt(b"lab A private variant", wrapped_key=wrapped, dataset_id=DATASET_A)

    with pytest.raises(DecryptionError):
        cipher.decrypt(blob, wrapped_key=wrapped, dataset_id=DATASET_B)


def test_data_key_from_one_dataset_cannot_unwrap_for_another(cipher: EnvelopeCipher) -> None:
    """Dataset ID is bound as AAD on the DEK wrap too."""
    wrapped = cipher.generate_data_key(DATASET_A)
    relabelled = wrapped.model_copy(update={"dataset_id": DATASET_B})

    with pytest.raises(DecryptionError):
        cipher.unwrap_data_key(relabelled)


def test_wrong_master_key_cannot_unwrap(cipher: EnvelopeCipher) -> None:
    wrapped = cipher.generate_data_key(DATASET_A)
    attacker = EnvelopeCipher(master_kek=OTHER_KEK, kek_id="kek-test")

    with pytest.raises(DecryptionError):
        attacker.unwrap_data_key(wrapped)


def test_dek_from_a_different_dataset_cannot_decrypt(cipher: EnvelopeCipher) -> None:
    key_a = cipher.generate_data_key(DATASET_A)
    key_b = cipher.generate_data_key(DATASET_B)
    blob = cipher.encrypt(b"lab A payload", wrapped_key=key_a, dataset_id=DATASET_A)

    with pytest.raises(DecryptionError):
        cipher.decrypt(blob, wrapped_key=key_b, dataset_id=DATASET_A)


# --- Key rotation -----------------------------------------------------------


def test_rewrap_preserves_plaintext_without_re_encrypting_data(cipher: EnvelopeCipher) -> None:
    """Rotating the master KEK must not require touching the ciphertext.

    This is the operational payoff of envelope encryption: rotation rewraps
    small DEKs instead of re-encrypting every genomic record.
    """
    wrapped = cipher.generate_data_key(DATASET_A)
    plaintext = b"variant call payload"
    blob = cipher.encrypt(plaintext, wrapped_key=wrapped, dataset_id=DATASET_A)

    rotated = EnvelopeCipher(master_kek=OTHER_KEK, kek_id="kek-2")
    rewrapped = cipher.rewrap_data_key(wrapped, new_cipher=rotated)

    # Ciphertext object is untouched; only the wrapped key changed.
    assert rotated.decrypt(blob, wrapped_key=rewrapped, dataset_id=DATASET_A) == plaintext
    assert rewrapped.kek_id == "kek-2"
    assert rewrapped.wrapped_dek != wrapped.wrapped_dek


def test_old_kek_cannot_unwrap_after_rotation(cipher: EnvelopeCipher) -> None:
    wrapped = cipher.generate_data_key(DATASET_A)
    rotated = EnvelopeCipher(master_kek=OTHER_KEK, kek_id="kek-2")
    rewrapped = cipher.rewrap_data_key(wrapped, new_cipher=rotated)

    with pytest.raises(DecryptionError):
        cipher.unwrap_data_key(rewrapped)


def test_rewrap_is_recorded_in_kek_id(cipher: EnvelopeCipher) -> None:
    """kek_id lets an operator find keys still wrapped under a retired KEK."""
    wrapped = cipher.generate_data_key(DATASET_A)
    assert wrapped.kek_id == "kek-test"


# --- Serialization ----------------------------------------------------------


def test_blob_survives_base64_persistence_round_trip(cipher: EnvelopeCipher) -> None:
    """Blobs are stored base64-encoded in text columns; encoding must be lossless."""
    wrapped = cipher.generate_data_key(DATASET_A)
    plaintext = b"\x00\xff\xfe binary-ish genomic payload \x01"
    blob = cipher.encrypt(plaintext, wrapped_key=wrapped, dataset_id=DATASET_A)

    encoded = blob.to_storage()
    restored = type(blob).from_storage(encoded)

    assert cipher.decrypt(restored, wrapped_key=wrapped, dataset_id=DATASET_A) == plaintext


def test_wrapped_key_survives_storage_round_trip(cipher: EnvelopeCipher) -> None:
    wrapped = cipher.generate_data_key(DATASET_A)

    restored = WrappedKey.from_storage(wrapped.to_storage())

    assert cipher.unwrap_data_key(restored) == cipher.unwrap_data_key(wrapped)


def test_from_storage_rejects_malformed_input() -> None:
    with pytest.raises(ValueError):
        WrappedKey.from_storage("not-valid-base64-json!!!")


def test_empty_plaintext_round_trips(cipher: EnvelopeCipher) -> None:
    """Edge case: GCM handles zero-length plaintext, tag still authenticates."""
    wrapped = cipher.generate_data_key(DATASET_A)
    blob = cipher.encrypt(b"", wrapped_key=wrapped, dataset_id=DATASET_A)
    assert cipher.decrypt(blob, wrapped_key=wrapped, dataset_id=DATASET_A) == b""


def test_large_payload_round_trips(cipher: EnvelopeCipher) -> None:
    wrapped = cipher.generate_data_key(DATASET_A)
    plaintext = base64.b64encode(os.urandom(1_000_000))
    blob = cipher.encrypt(plaintext, wrapped_key=wrapped, dataset_id=DATASET_A)
    assert cipher.decrypt(blob, wrapped_key=wrapped, dataset_id=DATASET_A) == plaintext
