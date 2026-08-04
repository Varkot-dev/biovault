"""Dataset endpoints.

Every handler follows the same shape:

    1. Load the resource from the database to learn its true tenant.
    2. Call `authorize()`, which decides and audits.
    3. Return 404 on denial — never 403.

Step 1 matters: the resource's tenant must come from the database, never from
the request. Trusting a client-supplied tenant would make cross-tenant denial
bypassable by lying about ownership.

Step 3 matters: a 403 confirms the resource exists. Enumerating dataset IDs
against a 403/404 boundary maps another lab's holdings without reading a single
record. Both denial cases return an identical 404.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import func, select

from biovault.api.dependencies import CurrentPrincipal, TenantSession
from biovault.api.rate_limit import limiter
from biovault.audit.recorder import authorize
from biovault.authz.policy import Action, ResourceRef
from biovault.config import get_settings
from biovault.crypto.envelope import DecryptionError, EncryptedBlob, EnvelopeCipher, WrappedKey
from biovault.models.tables import Dataset, DatasetKey, GenomicRecord
from biovault.schemas.datasets import (
    DatasetSummary,
    RecordQuery,
    RecordResponse,
    UploadRequest,
    UploadResponse,
)

router = APIRouter(prefix="/datasets", tags=["datasets"])

# Denials and missing resources are indistinguishable by design.
_NOT_FOUND = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="dataset not found")


def _cipher() -> EnvelopeCipher:
    settings = get_settings()
    return EnvelopeCipher(
        master_kek=settings.master_kek_bytes(), kek_id=settings.master_kek_id
    )


def _load_dataset(session: TenantSession, dataset_id: str) -> Dataset | None:
    """Load a dataset. RLS already restricts this to the caller's tenant."""
    return session.execute(
        select(Dataset).where(Dataset.id == dataset_id)
    ).scalar_one_or_none()


def _load_wrapped_key(session: TenantSession, dataset_id: str) -> WrappedKey:
    row = session.execute(
        select(DatasetKey).where(DatasetKey.dataset_id == dataset_id)
    ).scalar_one_or_none()
    if row is None:
        raise _NOT_FOUND
    return WrappedKey.from_storage(row.wrapped_key)


@router.get("", response_model=list[DatasetSummary])
@limiter.limit(lambda: get_settings().rate_limit)
def list_datasets(
    request: Request,
    principal: CurrentPrincipal,
    session: TenantSession,
) -> list[DatasetSummary]:
    """List datasets visible to the caller.

    RLS scopes the query to the caller's tenant. The per-dataset policy check
    then filters to what this principal may actually read, so a researcher
    sees only granted datasets rather than everything in their lab.
    """
    rows = session.execute(select(Dataset)).scalars().all()

    visible: list[DatasetSummary] = []
    for dataset in rows:
        decision = authorize(
            session,
            principal=principal,
            action=Action.READ,
            resource=ResourceRef(tenant_id=dataset.tenant_id, dataset_id=dataset.id),
        )
        if not decision.allowed:
            continue
        count = session.execute(
            select(func.count())
            .select_from(GenomicRecord)
            .where(GenomicRecord.dataset_id == dataset.id)
        ).scalar_one()
        visible.append(
            DatasetSummary(
                id=dataset.id,
                name=dataset.name,
                description=dataset.description,
                record_count=count,
                created_at=dataset.created_at,
            )
        )
    return visible


@router.post("/{dataset_id}/records", response_model=UploadResponse)
@limiter.limit(lambda: get_settings().rate_limit)
def upload_records(
    request: Request,
    dataset_id: str,
    payload: UploadRequest,
    principal: CurrentPrincipal,
    session: TenantSession,
) -> UploadResponse:
    """Upload records, encrypting each payload under the dataset's data key."""
    dataset = _load_dataset(session, dataset_id)
    if dataset is None:
        # Still audit the attempt: probing for dataset ids is a signal.
        authorize(
            session,
            principal=principal,
            action=Action.WRITE,
            resource=ResourceRef(tenant_id=principal.tenant_id, dataset_id=dataset_id),
        )
        raise _NOT_FOUND

    decision = authorize(
        session,
        principal=principal,
        action=Action.WRITE,
        resource=ResourceRef(tenant_id=dataset.tenant_id, dataset_id=dataset.id),
    )
    if not decision.allowed:
        raise _NOT_FOUND

    cipher = _cipher()
    wrapped = _load_wrapped_key(session, dataset.id)

    for record in payload.records:
        blob = cipher.encrypt(
            record.payload.encode(), wrapped_key=wrapped, dataset_id=dataset.id
        )
        session.add(
            GenomicRecord(
                tenant_id=dataset.tenant_id,
                dataset_id=dataset.id,
                specimen_label=record.specimen_label,
                gene_symbol=record.gene_symbol,
                contains_phi=record.contains_phi,
                payload_ciphertext=blob.to_storage(),
            )
        )
    session.flush()

    return UploadResponse(dataset_id=dataset.id, accepted=len(payload.records))


@router.post("/{dataset_id}/query", response_model=list[RecordResponse])
@limiter.limit(lambda: get_settings().rate_limit)
def query_records(
    request: Request,
    dataset_id: str,
    query: RecordQuery,
    principal: CurrentPrincipal,
    session: TenantSession,
) -> list[RecordResponse]:
    """Query and decrypt records the caller is authorized to read.

    PHI-bearing records are filtered per-record through the policy, so a
    caller without clearance receives the non-PHI subset rather than an error.
    """
    dataset = _load_dataset(session, dataset_id)
    if dataset is None:
        authorize(
            session,
            principal=principal,
            action=Action.READ,
            resource=ResourceRef(tenant_id=principal.tenant_id, dataset_id=dataset_id),
        )
        raise _NOT_FOUND

    decision = authorize(
        session,
        principal=principal,
        action=Action.READ,
        resource=ResourceRef(tenant_id=dataset.tenant_id, dataset_id=dataset.id),
    )
    if not decision.allowed:
        raise _NOT_FOUND

    statement = select(GenomicRecord).where(GenomicRecord.dataset_id == dataset.id)

    if query.specimen_label is not None:
        # Escape LIKE metacharacters so a caller cannot widen their own filter
        # into a full scan. The value is still bound, never concatenated.
        escaped = (
            query.specimen_label.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        statement = statement.where(
            GenomicRecord.specimen_label.like(f"%{escaped}%", escape="\\")
        )

    if query.contains_phi is not None:
        statement = statement.where(GenomicRecord.contains_phi == query.contains_phi)

    statement = statement.order_by(GenomicRecord.specimen_label)
    statement = statement.limit(query.limit).offset(query.offset)

    rows = session.execute(statement).scalars().all()

    cipher = _cipher()
    wrapped = _load_wrapped_key(session, dataset.id)

    results: list[RecordResponse] = []
    for row in rows:
        record_decision = authorize(
            session,
            principal=principal,
            action=Action.READ,
            resource=ResourceRef(
                tenant_id=row.tenant_id,
                dataset_id=row.dataset_id,
                record_id=row.id,
                contains_phi=row.contains_phi,
            ),
        )
        if not record_decision.allowed:
            continue

        try:
            plaintext = cipher.decrypt(
                EncryptedBlob.from_storage(row.payload_ciphertext),
                wrapped_key=wrapped,
                dataset_id=row.dataset_id,
            )
        except (DecryptionError, ValueError) as exc:
            # Authentication failure here means the stored ciphertext was
            # tampered with or relocated. Fail the request rather than
            # returning partial results that silently omit affected records.
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="record integrity check failed",
            ) from exc

        results.append(
            RecordResponse(
                id=row.id,
                specimen_label=row.specimen_label,
                contains_phi=row.contains_phi,
                payload=plaintext.decode(),
            )
        )

    return results


@router.delete("/{dataset_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(lambda: get_settings().rate_limit)
def delete_dataset(
    request: Request,
    dataset_id: str,
    principal: CurrentPrincipal,
    session: TenantSession,
) -> None:
    """Delete a dataset and its records."""
    dataset = _load_dataset(session, dataset_id)
    if dataset is None:
        authorize(
            session,
            principal=principal,
            action=Action.DELETE,
            resource=ResourceRef(tenant_id=principal.tenant_id, dataset_id=dataset_id),
        )
        raise _NOT_FOUND

    decision = authorize(
        session,
        principal=principal,
        action=Action.DELETE,
        resource=ResourceRef(tenant_id=dataset.tenant_id, dataset_id=dataset.id),
    )
    if not decision.allowed:
        raise _NOT_FOUND

    session.delete(dataset)
    session.flush()
