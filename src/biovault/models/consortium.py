"""Consortium participation and inbound extraction accounting.

Kept separate from `biovault.models.tables` because these tables answer a
different question. The tables there describe what a lab *holds*; these
describe what a lab has *agreed to expose* and how much has been taken from it.

Both tables are tenant-scoped to the lab being queried — the data source —
rather than to the querier. That is the whole point: a lab's consent and its
extraction ceiling must be readable and enforceable from the lab's own
perspective, not from that of whoever is asking.
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
from sqlalchemy.orm import Mapped, mapped_column

from biovault.models.tables import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class ConsortiumParticipation(Base):
    """A lab's opt-in decision for federated queries against its data.

    Existence in `tenants` is deliberately NOT consent. A row here is required
    before a lab's records are scanned by another lab's federated query, and
    absence of a row means non-participation — so the default for any newly
    created tenant, or any tenant created before this table existed, is to be
    excluded rather than silently enrolled.

    ## Why a flag and not a delete

    `participating` is mutable and withdrawal flips it to False rather than
    removing the row. A deleted row is indistinguishable from a lab that never
    joined, which loses the fact that consent was given and later withdrawn —
    exactly the fact an ethics board or a data-sharing agreement audit needs.
    `withdrawn_at` and `withdrawal_reason` preserve it.

    Withdrawal takes effect on the next query. In-flight queries that already
    enumerated sites are not retroactively cancelled; the extraction ceiling
    below is what bounds damage in that window.
    """

    __tablename__ = "consortium_participation"
    __table_args__ = (
        UniqueConstraint("tenant_id", name="uq_consortium_participation_tenant"),
        Index("ix_consortium_participation_tenant", "tenant_id"),
        Index("ix_consortium_participation_active", "participating"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    participating: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Per-lab ceiling on epsilon extracted FROM this lab within the window.
    # Nullable so a lab that has not set one inherits the module default,
    # rather than being handed an unbounded ceiling by omission.
    inbound_epsilon_limit: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Who recorded the decision, so consent is attributable to a principal
    # rather than appearing spontaneously in the database.
    decided_by: Mapped[str] = mapped_column(String(64), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    withdrawn_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    withdrawal_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")


class InboundEpsilonEntry(Base):
    """One unit of epsilon extracted FROM this tenant by some querier.

    Append-only for the same reason as `PrivacyBudgetEntry`: a tenant able to
    delete rows here could be drained without limit, and — worse — the *querying*
    tenants are the parties who benefit from those deletions. UPDATE and DELETE
    are revoked from the application role at the GRANT level.

    `tenant_id` is the lab the data was taken from, NOT the lab that asked.
    The querier is recorded separately in `querying_tenant_id`. Getting these
    two backwards would make the ledger a duplicate of the outbound budget and
    silently reintroduce the gap it exists to close.
    """

    __tablename__ = "inbound_epsilon_entries"
    __table_args__ = (
        Index("ix_inbound_epsilon_tenant", "tenant_id"),
        Index("ix_inbound_epsilon_occurred", "occurred_at"),
        Index("ix_inbound_epsilon_querier", "querying_tenant_id"),
        Index("ix_inbound_epsilon_fingerprint", "query_fingerprint"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)

    # The lab whose records were scanned. RLS filters on this.
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # The lab that issued the query, and the acting principal within it.
    # Recorded so a lab can see WHO has been drawing on its patients, which is
    # the question a participation decision actually turns on.
    querying_tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)

    epsilon_extracted: Mapped[float] = mapped_column(Float, nullable=False)
    query_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
