"""Request and response models for dataset endpoints.

Validation happens at the boundary. Note what is *absent* from every request
model: no `tenant_id`, no `role`, no `user_id`. Those come from the verified
token. Accepting them from the client would let a caller assert their own
authorization context, which is the escalation path the design forbids.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

# Identifiers are constrained to a conservative charset. This is defence in
# depth, not the primary SQL-injection control -- queries are parameterized --
# but it also blocks path traversal and log-injection via crafted ids.
_ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"


class DatasetSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    description: str
    record_count: int
    created_at: datetime


class RecordUpload(BaseModel):
    """One record submitted for encrypted storage.

    `gene_symbol` is the one component of the variant call stored in the clear,
    so that federated cohort counts can filter without decrypting anything. It
    is optional because not every record is a variant call; records without one
    simply never match a federated gene query. See `models.tables.GenomicRecord`
    for why a bare gene name is safe unencrypted while the rest of the call is
    not — callers must not put coordinates or genotypes here.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    specimen_label: str = Field(min_length=1, max_length=120)
    gene_symbol: str = Field(default="", max_length=40)
    payload: str = Field(min_length=1, max_length=1_000_000)
    contains_phi: bool = False


class UploadRequest(BaseModel):
    """A batch of records destined for one dataset."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    records: list[RecordUpload] = Field(min_length=1, max_length=500)


class UploadResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    dataset_id: str
    accepted: int


class RecordResponse(BaseModel):
    """A decrypted record returned to an authorized caller."""

    model_config = ConfigDict(frozen=True)

    id: str
    specimen_label: str
    contains_phi: bool
    payload: str


class RecordQuery(BaseModel):
    """Filters for a record query.

    `specimen_label` is matched with a parameterized LIKE. The pattern is
    escaped before binding so a caller cannot turn a filter into a wildcard
    scan of the dataset.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    specimen_label: str | None = Field(default=None, max_length=120)
    contains_phi: bool | None = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class AuditEntryResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    actor_id: str
    actor_role: str
    action: str
    resource_type: str
    resource_id: str | None
    allowed: bool
    reason: str
    occurred_at: datetime
