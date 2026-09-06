import uuid
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI, HTTPException

from app.api.auth_deps import require_operator
from app.api.deps import get_db
from app.api.v1.targets import delete_target, router
from app.models.target import Target


@pytest.mark.parametrize("scan_active,discovery_active", [(True, False), (False, True)])
async def test_target_delete_rejects_active_jobs(scan_active, discovery_active):
    db = AsyncMock()
    db.get.return_value = Target(id=uuid.uuid4())
    db.scalar.side_effect = [
        uuid.uuid4() if scan_active else None,
        uuid.uuid4() if discovery_active else None,
    ]
    with pytest.raises(HTTPException) as error:
        await delete_target(uuid.uuid4(), db, object())
    assert error.value.status_code == 409
    db.delete.assert_not_awaited()
    db.commit.assert_not_awaited()


async def test_delete_missing_target_returns_404():
    db = AsyncMock()
    db.get.return_value = None
    with pytest.raises(HTTPException) as error:
        await delete_target(uuid.uuid4(), db, object())
    assert error.value.status_code == 404
    db.delete.assert_not_awaited()


async def test_delete_response_is_empty_and_locks_target():
    target = Target(id=uuid.uuid4())
    db = AsyncMock()
    db.get.return_value = target
    db.scalar.return_value = None
    response = await delete_target(target.id, db, object())
    assert response.status_code == 204
    assert response.body == b""
    db.get.assert_awaited_once_with(Target, target.id, with_for_update=True)
    db.delete.assert_awaited_once_with(target)
    db.commit.assert_awaited_once()


async def test_delete_requires_operator_permission():
    app = FastAPI()
    app.include_router(router)
    db = AsyncMock()

    async def denied():
        raise HTTPException(status_code=403, detail="Operator required")

    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_operator] = denied
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.delete(f"/targets/{uuid.uuid4()}")
    assert response.status_code == 403
    db.delete.assert_not_awaited()


async def test_delete_cascades_history_and_preserves_other_targets():
    from sqlalchemy import create_engine, event, select
    from sqlalchemy.orm import Session

    from app.models.base import Base
    from app.models.discovery import Discovery, DiscoveryStatus
    from app.models.finding import Evidence, Finding
    from app.models.scan import Scan, ScanStatus

    engine = create_engine("sqlite://")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with Session(engine) as session:
        target = Target(name="Delete fixture", target_type="webapp")
        other = Target(name="Keep fixture", target_type="webapp")
        session.add_all([target, other])
        session.flush()
        target_id, other_id = target.id, other.id
        scan = Scan(target_id=target_id, status=ScanStatus.COMPLETED)
        discovery = Discovery(target_id=target_id, status=DiscoveryStatus.COMPLETED)
        session.add_all([scan, discovery])
        session.flush()
        finding = Finding(
            target_id=target_id,
            scan_id=scan.id,
            detector_id="test",
            vulnerability_name="Test",
            severity="LOW",
            confidence="LOW",
        )
        session.add(finding)
        session.flush()
        session.add(Evidence(finding_id=finding.id, evidence_type="test", content={}))
        session.commit()

        class AsyncAdapter:
            async def get(self, *args, **kwargs):
                return session.get(*args, **kwargs)

            async def scalar(self, query):
                return session.scalar(query)

            async def delete(self, record):
                session.delete(record)

            async def commit(self):
                session.commit()

        await delete_target(target_id, AsyncAdapter(), object())
        session.expunge_all()
        assert session.get(Target, target_id) is None
        assert session.get(Target, other_id) is not None
        for model in (Scan, Discovery, Finding, Evidence):
            assert session.scalars(select(model)).all() == []
    engine.dispose()
