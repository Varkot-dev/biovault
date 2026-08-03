"""AES-256-GCM envelope encryption for genomics fields.

Two-tier key hierarchy:

    master KEK (env / KMS)  ──wraps──>  per-dataset DEK  ──encrypts──>  field data

Rotating the master KEK rewraps the small DEKs and never touches the bulk
ciphertext. Compromise of a single DEK is scoped to one dataset.

Both layers use AES-GCM, an AEAD construction, so tampering is detected rather
than silently decrypting to garbage. The dataset ID is bound as additional
authenticated data (AAD) at both layers, which means a ciphertext physically
relocated to a different dataset fails authentication.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Self

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict

AES_256_KEY_BYTES = 32
GCM_NONCE_BYTES = 12  # 96 bits, the size NIST SP 800-38D recommends for GCM

_AAD_DEK_PREFIX = b"biovault:dek:v1:"
_AAD_FIELD_PREFIX = b"biovault:field:v1:"


class DecryptionError(Exception):
    """Raised when authenticated decryption fails.

    Deliberately carries no detail about *why* it failed. Distinguishing "wrong
    key" from "tampered ciphertext" in an error message hands an attacker an
    oracle.
    """


class WrappedKey(BaseModel):
    """A per-dataset data key, encrypted under the master KEK.

    Safe to persist: the raw DEK is never present in this structure.
    """

    model_config = ConfigDict(frozen=True)

    dataset_id: str
    kek_id: str
    nonce: bytes
    wrapped_dek: bytes

    def to_storage(self) -> str:
        """Serialize to a base64 JSON string for a text column."""
        payload = json.dumps(
            {
                "dataset_id": self.dataset_id,
                "kek_id": self.kek_id,
                "nonce": base64.b64encode(self.nonce).decode(),
                "wrapped_dek": base64.b64encode(self.wrapped_dek).decode(),
            }
        )
        return base64.b64encode(payload.encode()).decode()

    @classmethod
    def from_storage(cls, encoded: str) -> Self:
        """Rebuild from `to_storage` output.

        Raises:
            ValueError: If the input is not well-formed.
        """
        try:
            payload = json.loads(base64.b64decode(encoded, validate=True))
            return cls(
                dataset_id=payload["dataset_id"],
                kek_id=payload["kek_id"],
                nonce=base64.b64decode(payload["nonce"], validate=True),
                wrapped_dek=base64.b64decode(payload["wrapped_dek"], validate=True),
            )
        except Exception as exc:
            raise ValueError("malformed wrapped key") from exc


class EncryptedBlob(BaseModel):
    """Ciphertext plus the nonce needed to decrypt it.

    The GCM authentication tag is appended to `ciphertext` by the underlying
    library, so it is not a separate field.
    """

    model_config = ConfigDict(frozen=True)

    nonce: bytes
    ciphertext: bytes

    def to_storage(self) -> str:
        payload = json.dumps(
            {
                "nonce": base64.b64encode(self.nonce).decode(),
                "ciphertext": base64.b64encode(self.ciphertext).decode(),
            }
        )
        return base64.b64encode(payload.encode()).decode()

    @classmethod
    def from_storage(cls, encoded: str) -> Self:
        try:
            payload = json.loads(base64.b64decode(encoded, validate=True))
            return cls(
                nonce=base64.b64decode(payload["nonce"], validate=True),
                ciphertext=base64.b64decode(payload["ciphertext"], validate=True),
            )
        except Exception as exc:
            raise ValueError("malformed encrypted blob") from exc


def _dek_aad(dataset_id: str, kek_id: str) -> bytes:
    """AAD binding a wrapped DEK to its dataset and KEK generation."""
    return _AAD_DEK_PREFIX + f"{dataset_id}:{kek_id}".encode()


def _field_aad(dataset_id: str) -> bytes:
    """AAD binding field ciphertext to its dataset."""
    return _AAD_FIELD_PREFIX + dataset_id.encode()


class EnvelopeCipher:
    """Envelope encryption bound to one master key-encryption key."""

    def __init__(self, *, master_kek: bytes, kek_id: str) -> None:
        """
        Args:
            master_kek: Exactly 32 bytes (AES-256).
            kek_id: Identifier for this KEK generation, recorded on every
                wrapped key so an operator can find keys still under a
                retired KEK during rotation.

        Raises:
            ValueError: If the key is not 32 bytes.
        """
        if len(master_kek) != AES_256_KEY_BYTES:
            raise ValueError(
                f"master KEK must be exactly {AES_256_KEY_BYTES} bytes for AES-256; "
                f"got {len(master_kek)}"
            )
        self._aead = AESGCM(master_kek)
        self._kek_id = kek_id

    @property
    def kek_id(self) -> str:
        return self._kek_id

    def generate_data_key(self, dataset_id: str) -> WrappedKey:
        """Mint a fresh 256-bit DEK for a dataset and return it wrapped."""
        dek = os.urandom(AES_256_KEY_BYTES)
        return self._wrap(dek, dataset_id=dataset_id)

    def _wrap(self, dek: bytes, *, dataset_id: str) -> WrappedKey:
        nonce = os.urandom(GCM_NONCE_BYTES)
        wrapped = self._aead.encrypt(nonce, dek, _dek_aad(dataset_id, self._kek_id))
        return WrappedKey(
            dataset_id=dataset_id,
            kek_id=self._kek_id,
            nonce=nonce,
            wrapped_dek=wrapped,
        )

    def unwrap_data_key(self, wrapped_key: WrappedKey) -> bytes:
        """Recover the raw DEK.

        Raises:
            DecryptionError: If the wrapped key was tampered with, was wrapped
                under a different master KEK, or has been relabelled to a
                different dataset.
        """
        try:
            return self._aead.decrypt(
                wrapped_key.nonce,
                wrapped_key.wrapped_dek,
                _dek_aad(wrapped_key.dataset_id, wrapped_key.kek_id),
            )
        except InvalidTag as exc:
            raise DecryptionError("unable to unwrap data key") from exc

    def encrypt(
        self, plaintext: bytes, *, wrapped_key: WrappedKey, dataset_id: str
    ) -> EncryptedBlob:
        """Encrypt a field value under the dataset's DEK."""
        dek = self.unwrap_data_key(wrapped_key)
        nonce = os.urandom(GCM_NONCE_BYTES)
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, _field_aad(dataset_id))
        return EncryptedBlob(nonce=nonce, ciphertext=ciphertext)

    def decrypt(self, blob: EncryptedBlob, *, wrapped_key: WrappedKey, dataset_id: str) -> bytes:
        """Decrypt a field value.

        Raises:
            DecryptionError: On any authentication failure — tampered
                ciphertext or nonce, wrong DEK, or a blob relocated to a
                different dataset.
        """
        dek = self.unwrap_data_key(wrapped_key)
        try:
            return AESGCM(dek).decrypt(blob.nonce, blob.ciphertext, _field_aad(dataset_id))
        except InvalidTag as exc:
            raise DecryptionError("unable to decrypt payload") from exc

    def rewrap_data_key(self, wrapped_key: WrappedKey, *, new_cipher: EnvelopeCipher) -> WrappedKey:
        """Re-wrap a DEK under a new master KEK, leaving ciphertext untouched.

        This is the key-rotation primitive. See `docs/key-rotation.md`.

        Raises:
            DecryptionError: If this cipher cannot unwrap the key.
        """
        dek = self.unwrap_data_key(wrapped_key)
        return new_cipher._wrap(dek, dataset_id=wrapped_key.dataset_id)
