"""Runtime configuration.

Secrets are read from the environment and validated at startup. There are no
default values for secret material: a missing or malformed key must crash the
process rather than silently fall back to something guessable.
"""

from __future__ import annotations

import base64
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AES_256_KEY_BYTES = 32
MIN_JWT_SECRET_CHARS = 32


class Settings(BaseSettings):
    """Application settings sourced from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    # --- Database ---
    postgres_user: str = Field(default="biovault_owner", alias="POSTGRES_USER")
    postgres_password: SecretStr = Field(alias="POSTGRES_PASSWORD")
    postgres_db: str = Field(default="biovault", alias="POSTGRES_DB")
    postgres_host: str = Field(default="localhost", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")

    app_db_user: str = Field(default="biovault_app", alias="BIOVAULT_APP_DB_USER")
    app_db_password: SecretStr = Field(alias="BIOVAULT_APP_DB_PASSWORD")

    # --- Encryption ---
    master_kek: SecretStr = Field(alias="BIOVAULT_MASTER_KEK")
    master_kek_id: str = Field(default="kek-1", alias="BIOVAULT_MASTER_KEK_ID")

    # --- JWT ---
    jwt_secret: SecretStr = Field(alias="BIOVAULT_JWT_SECRET")
    jwt_issuer: str = Field(default="https://biovault.local", alias="BIOVAULT_JWT_ISSUER")
    jwt_audience: str = Field(default="biovault-api", alias="BIOVAULT_JWT_AUDIENCE")
    access_token_ttl_seconds: int = Field(
        default=900, alias="BIOVAULT_ACCESS_TOKEN_TTL_SECONDS"
    )
    refresh_token_ttl_seconds: int = Field(
        default=604800, alias="BIOVAULT_REFRESH_TOKEN_TTL_SECONDS"
    )

    # --- OAuth ---
    oauth_client_id: str = Field(default="biovault-web", alias="BIOVAULT_OAUTH_CLIENT_ID")
    oauth_redirect_uri: str = Field(
        default="http://localhost:8000/auth/callback", alias="BIOVAULT_OAUTH_REDIRECT_URI"
    )

    # --- Runtime ---
    env: Literal["development", "test", "production"] = Field(
        default="development", alias="BIOVAULT_ENV"
    )
    rate_limit: str = Field(default="100/minute", alias="BIOVAULT_RATE_LIMIT")

    @field_validator("master_kek")
    @classmethod
    def _validate_kek(cls, value: SecretStr) -> SecretStr:
        """Reject a master key that is not exactly 256 bits of base64."""
        raw = value.get_secret_value()
        if not raw:
            raise ValueError(
                "BIOVAULT_MASTER_KEK is not set. Generate one with: "
                'python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"'
            )
        try:
            decoded = base64.b64decode(raw, validate=True)
        except Exception as exc:  # noqa: BLE001 - surfaced as a config error
            raise ValueError("BIOVAULT_MASTER_KEK must be valid base64") from exc
        if len(decoded) != AES_256_KEY_BYTES:
            raise ValueError(
                f"BIOVAULT_MASTER_KEK must decode to exactly {AES_256_KEY_BYTES} bytes "
                f"(AES-256); got {len(decoded)}"
            )
        return value

    @field_validator("jwt_secret")
    @classmethod
    def _validate_jwt_secret(cls, value: SecretStr) -> SecretStr:
        """Reject short JWT secrets, which are brute-forceable offline."""
        raw = value.get_secret_value()
        if len(raw) < MIN_JWT_SECRET_CHARS:
            raise ValueError(
                f"BIOVAULT_JWT_SECRET must be at least {MIN_JWT_SECRET_CHARS} characters"
            )
        return value

    def master_kek_bytes(self) -> bytes:
        """Return the decoded 32-byte master key-encryption key."""
        return base64.b64decode(self.master_kek.get_secret_value(), validate=True)

    def database_url(self, *, as_owner: bool = False) -> str:
        """Build a SQLAlchemy URL.

        Args:
            as_owner: Connect as the owning/superuser role. Reserved for
                migrations and RLS setup. Request paths must use the default
                (least-privilege) role so row-level security applies.
        """
        user = self.postgres_user if as_owner else self.app_db_user
        password = (
            self.postgres_password if as_owner else self.app_db_password
        ).get_secret_value()
        return (
            f"postgresql+psycopg://{user}:{password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()  # type: ignore[call-arg]
