"""SQLAlchemy table definitions.

Tenant-scoped tables carry a `tenant_id` column that row-level security
policies filter on. See `biovault.db.rls` for the policies themselves.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


class Tenant(Base):
    """A research lab. The isolation boundary."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class User(Base):
    """A principal belonging to exactly one tenant.

    A user belongs to one lab. Cross-lab collaboration would be modelled as
    separate accounts, deliberately: a single account spanning tenants would
    make the isolation boundary depend on request context rather than identity.
    """

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("email", name="uq_users_email"),
        Index("ix_users_tenant", "tenant_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    phi_cleared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    grants: Mapped[list[DatasetGrant]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Dataset(Base):
    """A genomics dataset owned by one tenant."""

    __tablename__ = "datasets"
    __table_args__ = (Index("ix_datasets_tenant", "tenant_id"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    records: Mapped[list[GenomicRecord]] = relationship(
        back_populates="dataset", cascade="all, delete-orphan"
    )


class DatasetKey(Base):
    """The wrapped data-encryption key for one dataset.

    Stores only the wrapped form. `kek_id` identifies which master key
    generation wrapped it, so rotation can find stragglers with a GROUP BY.
    """

    __tablename__ = "dataset_keys"
    __table_args__ = (
        UniqueConstraint("dataset_id", name="uq_dataset_keys_dataset"),
        Index("ix_dataset_keys_tenant", "tenant_id"),
        Index("ix_dataset_keys_kek", "kek_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    dataset_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False
    )
    kek_id: Mapped[str] = mapped_column(String(64), nullable=False)
    wrapped_key: Mapped[str] = mapped_column(Text, nullable=False)


class GenomicRecord(Base):
    """One record. Sensitive payload is stored encrypted.

    `payload_ciphertext` holds a serialized `EncryptedBlob`. Nothing readable
    is stored in the clear beyond the non-sensitive identifiers needed to
    index and authorize.
    """

    __tablename__ = "genomic_records"
    __table_args__ = (
        Index("ix_genomic_records_tenant", "tenant_id"),
        Index("ix_genomic_records_dataset", "dataset_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    dataset_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False
    )
    specimen_label: Mapped[str] = mapped_column(String(120), nullable=False)
    contains_phi: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    payload_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    dataset: Mapped[Dataset] = relationship(back_populates="records")


class DatasetGrant(Base):
    """An explicit per-dataset grant to a user."""

    __tablename__ = "dataset_grants"
    __table_args__ = (
        UniqueConstraint("user_id", "dataset_id", name="uq_grant_user_dataset"),
        Index("ix_dataset_grants_tenant", "tenant_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    dataset_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False
    )

    user: Mapped[User] = relationship(back_populates="grants")


class AuditEntry(Base):
    """Append-only record of an access decision.

    UPDATE and DELETE are revoked from the application role at the database
    level, so append-only is enforced by Postgres rather than by convention.
    See `biovault.db.rls`.
    """

    __tablename__ = "audit_entries"
    __table_args__ = (
        Index("ix_audit_tenant", "tenant_id"),
        Index("ix_audit_occurred", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class PrivacyBudgetEntry(Base):
    """One debit against a tenant's differential-privacy budget.

    Append-only, like the audit log and for the same reason: a tenant able to
    delete its own budget entries has an unlimited query allowance, which
    removes the privacy guarantee entirely. UPDATE and DELETE are revoked from
    the application role at the GRANT level.

    `query_fingerprint` records what the budget was spent on, making a
    repeated-query averaging attack visible to an auditor as a run of
    identical fingerprints.
    """

    __tablename__ = "privacy_budget_entries"
    __table_args__ = (
        Index("ix_privacy_budget_tenant", "tenant_id"),
        Index("ix_privacy_budget_occurred", "occurred_at"),
        Index("ix_privacy_budget_fingerprint", "query_fingerprint"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    epsilon_spent: Mapped[float] = mapped_column(Float, nullable=False)
    query_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RefreshToken(Base):
    """A refresh token in a rotation family.

    `family_id` links every token descended from one login. Presenting an
    already-rotated token indicates theft, and the whole family is revoked.
    See `biovault.auth.refresh`.
    """

    __tablename__ = "refresh_tokens"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_refresh_token_hash"),
        Index("ix_refresh_family", "family_id"),
        Index("ix_refresh_user", "user_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    family_id: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuthorizationCode(Base):
    """A short-lived OAuth 2.0 authorization code bound to a PKCE challenge."""

    __tablename__ = "authorization_codes"
    __table_args__ = (UniqueConstraint("code_hash", name="uq_auth_code_hash"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    client_id: Mapped[str] = mapped_column(String(128), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(500), nullable=False)
    code_challenge: Mapped[str] = mapped_column(String(128), nullable=False)
    code_challenge_method: Mapped[str] = mapped_column(String(8), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
