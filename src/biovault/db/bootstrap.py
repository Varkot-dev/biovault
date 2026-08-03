"""Create schema, install RLS, and seed synthetic data.

Runs as the schema owner. Idempotent: safe to run on every container boot.

All seeded data is synthetic. Specimen labels and variant payloads are
generated, not derived from any real genomic source.
"""

from __future__ import annotations

import logging

from sqlalchemy import select

from biovault.config import get_settings
from biovault.crypto.envelope import EnvelopeCipher
from biovault.db.rls import apply_rls_policies, set_app_role_password
from biovault.db.session import owner_engine
from biovault.models.tables import (
    Base,
    Dataset,
    DatasetGrant,
    DatasetKey,
    GenomicRecord,
    Tenant,
    User,
)
from biovault.seed.synthetic import SYNTHETIC_TENANTS, build_synthetic_records

logger = logging.getLogger(__name__)


def bootstrap() -> None:
    """Bring the database to a ready state."""
    settings = get_settings()
    engine = owner_engine()

    with engine.begin() as conn:
        Base.metadata.create_all(conn)
        logger.info("schema created")

    with engine.begin() as conn:
        apply_rls_policies(conn, app_role=settings.app_db_user)
        set_app_role_password(
            conn,
            app_role=settings.app_db_user,
            password=settings.app_db_password.get_secret_value(),
        )
        logger.info("row-level security applied")

    _seed(settings)
    logger.info("bootstrap complete")


def _seed(settings) -> None:  # noqa: ANN001 - Settings, avoided for import cycle clarity
    """Insert synthetic tenants, users, datasets, and records if absent.

    Seeding runs as the owner because it deliberately spans all three tenants,
    which no runtime request is ever allowed to do.
    """
    from sqlalchemy.orm import Session

    cipher = EnvelopeCipher(
        master_kek=settings.master_kek_bytes(), kek_id=settings.master_kek_id
    )

    with Session(owner_engine(), future=True) as session:
        if session.execute(select(Tenant).limit(1)).first() is not None:
            logger.info("seed data already present, skipping")
            return

        # Tenants are inserted and flushed first. SQLAlchemy batches inserts by
        # mapper rather than by the order objects were added, so without an
        # explicit flush every Dataset row is sent before any Tenant row and
        # the foreign key fails.
        for spec in SYNTHETIC_TENANTS:
            session.add(Tenant(id=spec.tenant_id, name=spec.name))
        session.flush()

        for spec in SYNTHETIC_TENANTS:
            for user_spec in spec.users:
                session.add(
                    User(
                        id=user_spec.user_id,
                        tenant_id=spec.tenant_id,
                        email=user_spec.email,
                        role=user_spec.role.value,
                        phi_cleared=user_spec.phi_cleared,
                    )
                )

            for dataset_spec in spec.datasets:
                session.add(
                    Dataset(
                        id=dataset_spec.dataset_id,
                        tenant_id=spec.tenant_id,
                        name=dataset_spec.name,
                        description=dataset_spec.description,
                    )
                )

                wrapped = cipher.generate_data_key(dataset_spec.dataset_id)
                session.add(
                    DatasetKey(
                        tenant_id=spec.tenant_id,
                        dataset_id=dataset_spec.dataset_id,
                        kek_id=wrapped.kek_id,
                        wrapped_key=wrapped.to_storage(),
                    )
                )

                for record in build_synthetic_records(dataset_spec):
                    blob = cipher.encrypt(
                        record.payload.encode(),
                        wrapped_key=wrapped,
                        dataset_id=dataset_spec.dataset_id,
                    )
                    session.add(
                        GenomicRecord(
                            id=record.record_id,
                            tenant_id=spec.tenant_id,
                            dataset_id=dataset_spec.dataset_id,
                            specimen_label=record.specimen_label,
                            contains_phi=record.contains_phi,
                            payload_ciphertext=blob.to_storage(),
                        )
                    )

        # Users and datasets must exist before grants reference both.
        session.flush()

        for spec in SYNTHETIC_TENANTS:
            for grant in spec.grants:
                session.add(
                    DatasetGrant(
                        tenant_id=spec.tenant_id,
                        user_id=grant.user_id,
                        dataset_id=grant.dataset_id,
                    )
                )

        session.commit()
        logger.info("synthetic seed data inserted")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    bootstrap()
