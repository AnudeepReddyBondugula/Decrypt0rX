"""API tests run against a real Postgres - the queries use JSONB, date_trunc
and enum casts, none of which SQLite would exercise faithfully."""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest
import pytest_asyncio

API_ROOT = Path(__file__).resolve().parents[1]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

TEST_DB = os.getenv(
    "DECRYPT0RX_TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres@127.0.0.1:55432/decrypt0rx_test",
)

ADMIN_EMAIL = "admin@decrypt0rx.io"
ADMIN_PASSWORD = "bootstrap-password-123"

os.environ.update(
    DECRYPT0RX_DATABASE_URL=TEST_DB,
    DECRYPT0RX_MASTER_KEY=base64.b64encode(b"0" * 32).decode(),
    DECRYPT0RX_JWT_SECRET="test-jwt-secret-not-for-production",
    DECRYPT0RX_BOOTSTRAP_ADMIN_EMAIL=ADMIN_EMAIL,
    DECRYPT0RX_BOOTSTRAP_ADMIN_PASSWORD=ADMIN_PASSWORD,
    DECRYPT0RX_STORAGE_BACKEND="local",
    DECRYPT0RX_LOCAL_STORAGE_PATH="/tmp/decrypt0rx-test-bodies",
    DECRYPT0RX_REDIS_URL="redis://127.0.0.1:1/0",  # deliberately unreachable
    DECRYPT0RX_LOG_LEVEL="WARNING",
)


@pytest_asyncio.fixture
async def client():
    from httpx import ASGITransport, AsyncClient

    from app.main import create_app

    app = create_app()
    async with app.router.lifespan_context(app):
        await _truncate(app)
        async with app.state.session_factory() as session:
            from app.seed import ensure_admin, ensure_default_policies

            await ensure_admin(session, app.state.settings)
            await ensure_default_policies(session)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://testserver"
        ) as http:
            http.app = app
            yield http


async def _truncate(app) -> None:
    from sqlalchemy import text

    async with app.state.engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE flows, policy_rules, certificate_authorities, users, "
                "audit_logs, proxy_nodes RESTART IDENTITY CASCADE"
            )
        )


@pytest_asyncio.fixture
async def admin_token(client):
    response = await client.post(
        "/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


@pytest.fixture
def auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}
