"""Synthetic tenant, user, and genomics fixtures.

Everything here is fabricated. Specimen labels are sequential identifiers and
variant payloads are drawn from a small fixed vocabulary of well-known public
variant *names* with invented coordinates and genotypes. No real individual's
genomic data, and nothing resembling PHI, appears in this file or is derivable
from it.

The three labs are shaped to make isolation testable:

- Each lab holds datasets no other lab can see.
- Dataset IDs are distinct across labs, so a cross-tenant test that passes
  cannot be passing by coincidence of a shared identifier.
- Each lab has one user per role, so role behaviour can be compared across
  tenants.
"""

from __future__ import annotations

from typing import Final, NamedTuple

from biovault.authz.policy import Role


class UserSpec(NamedTuple):
    user_id: str
    email: str
    role: Role
    phi_cleared: bool = False


class DatasetSpec(NamedTuple):
    dataset_id: str
    name: str
    description: str
    record_count: int
    phi_record_count: int


class GrantSpec(NamedTuple):
    user_id: str
    dataset_id: str


class TenantSpec(NamedTuple):
    tenant_id: str
    name: str
    users: tuple[UserSpec, ...]
    datasets: tuple[DatasetSpec, ...]
    grants: tuple[GrantSpec, ...]


class SyntheticRecord(NamedTuple):
    record_id: str
    specimen_label: str
    payload: str
    contains_phi: bool


# Fabricated variant vocabulary. Gene names are public knowledge; the
# coordinates, genotypes, and depths below are invented.
_VARIANT_VOCAB: Final[tuple[str, ...]] = (
    "BRCA1:c.0000A>T:GT=0/1:DP=42",
    "TP53:c.0000G>C:GT=1/1:DP=37",
    "CFTR:c.0000delT:GT=0/1:DP=55",
    "HBB:c.0000A>G:GT=0/0:DP=61",
    "APOE:c.0000C>T:GT=0/1:DP=48",
)


BROAD = TenantSpec(
    tenant_id="lab-broad",
    name="Broad Institute Genomics Core (synthetic)",
    users=(
        UserSpec("u-broad-admin", "admin@broad.example", Role.LAB_ADMIN, phi_cleared=True),
        UserSpec("u-broad-research", "researcher@broad.example", Role.RESEARCHER),
        UserSpec("u-broad-auditor", "auditor@broad.example", Role.AUDITOR),
        UserSpec("u-broad-readonly", "readonly@broad.example", Role.READ_ONLY),
    ),
    datasets=(
        DatasetSpec("ds-broad-cohort-1", "Cardiac cohort A", "Synthetic cardiac panel", 6, 2),
        DatasetSpec("ds-broad-cohort-2", "Cardiac cohort B", "Synthetic cardiac panel", 4, 0),
    ),
    grants=(
        GrantSpec("u-broad-research", "ds-broad-cohort-1"),
        GrantSpec("u-broad-readonly", "ds-broad-cohort-1"),
    ),
)

SANGER = TenantSpec(
    tenant_id="lab-sanger",
    name="Sanger Sequencing Unit (synthetic)",
    users=(
        UserSpec("u-sanger-admin", "admin@sanger.example", Role.LAB_ADMIN, phi_cleared=True),
        UserSpec("u-sanger-research", "researcher@sanger.example", Role.RESEARCHER,
                 phi_cleared=True),
        UserSpec("u-sanger-auditor", "auditor@sanger.example", Role.AUDITOR),
        UserSpec("u-sanger-readonly", "readonly@sanger.example", Role.READ_ONLY),
    ),
    datasets=(
        DatasetSpec("ds-sanger-onco-1", "Oncology panel", "Synthetic oncology panel", 5, 3),
    ),
    grants=(GrantSpec("u-sanger-research", "ds-sanger-onco-1"),),
)

RIKEN = TenantSpec(
    tenant_id="lab-riken",
    name="RIKEN Population Genomics (synthetic)",
    users=(
        UserSpec("u-riken-admin", "admin@riken.example", Role.LAB_ADMIN),
        UserSpec("u-riken-research", "researcher@riken.example", Role.RESEARCHER),
        UserSpec("u-riken-auditor", "auditor@riken.example", Role.AUDITOR),
        UserSpec("u-riken-readonly", "readonly@riken.example", Role.READ_ONLY),
    ),
    datasets=(
        DatasetSpec("ds-riken-pop-1", "Population reference", "Synthetic population set", 7, 0),
    ),
    grants=(GrantSpec("u-riken-research", "ds-riken-pop-1"),),
)

SYNTHETIC_TENANTS: Final[tuple[TenantSpec, ...]] = (BROAD, SANGER, RIKEN)


def build_synthetic_records(dataset: DatasetSpec) -> tuple[SyntheticRecord, ...]:
    """Generate deterministic synthetic records for a dataset.

    Deterministic rather than random so that a failing test reproduces exactly.
    """
    records: list[SyntheticRecord] = []
    for index in range(dataset.record_count):
        variant = _VARIANT_VOCAB[index % len(_VARIANT_VOCAB)]
        records.append(
            SyntheticRecord(
                record_id=f"{dataset.dataset_id}-rec-{index:03d}",
                specimen_label=f"SPEC-{dataset.dataset_id[-4:].upper()}-{index:03d}",
                payload=f"{variant};dataset={dataset.dataset_id};idx={index}",
                contains_phi=index < dataset.phi_record_count,
            )
        )
    return tuple(records)
