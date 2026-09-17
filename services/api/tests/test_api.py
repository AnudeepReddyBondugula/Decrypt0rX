"""Control-plane behaviour: auth, RBAC, CA lifecycle, policy and flow queries."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from .conftest import ADMIN_EMAIL, ADMIN_PASSWORD

pytestmark = pytest.mark.asyncio


# ------------------------------------------------------------------- auth


async def test_login_succeeds_and_returns_the_user(client):
    response = await client.post(
        "/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["role"] == "admin"
    assert body["token_type"] == "bearer"


async def test_login_rejects_a_wrong_password(client):
    response = await client.post(
        "/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong-password"}
    )
    assert response.status_code == 401
    assert "Invalid email or password" in response.text


async def test_unauthenticated_requests_are_refused(client):
    assert (await client.get("/api/v1/policies")).status_code == 401
    assert (await client.get("/api/v1/flows")).status_code == 401


# --------------------------------------------------------------------- CA


async def test_generate_ca_activates_and_never_leaks_the_key(client, auth):
    response = await client.post(
        "/api/v1/ca/generate",
        json={"name": "Primary", "common_name": "Acme Root", "valid_days": 365},
        headers=auth,
    )
    assert response.status_code == 201, response.text
    ca = response.json()
    assert ca["is_active"] is True
    assert ca["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "key" not in " ".join(k for k in ca if "key_encrypted" in k)
    assert "PRIVATE KEY" not in response.text

    active = await client.get("/api/v1/ca/active", headers=auth)
    assert active.json()["fingerprint_sha256"] == ca["fingerprint_sha256"]


async def test_activating_a_second_ca_deactivates_the_first(client, auth):
    first = (await client.post(
        "/api/v1/ca/generate", json={"name": "First"}, headers=auth
    )).json()
    second = (await client.post(
        "/api/v1/ca/generate", json={"name": "Second", "activate": False}, headers=auth
    )).json()

    await client.post(f"/api/v1/ca/{second['id']}/activate", headers=auth)
    listing = {ca["id"]: ca["is_active"] for ca in (
        await client.get("/api/v1/ca", headers=auth)
    ).json()}
    assert listing[second["id"]] is True
    assert listing[first["id"]] is False


async def test_the_active_ca_cannot_be_deleted(client, auth):
    ca = (await client.post(
        "/api/v1/ca/generate", json={"name": "Only"}, headers=auth
    )).json()
    response = await client.delete(f"/api/v1/ca/{ca['id']}", headers=auth)
    assert response.status_code == 400
    assert "Activate a different CA" in response.text


async def test_public_root_certificate_needs_no_login(client, auth):
    await client.post("/api/v1/ca/generate", json={"name": "Public"}, headers=auth)
    response = await client.get("/api/v1/ca/public/root.crt")
    assert response.status_code == 200
    assert response.text.startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE KEY" not in response.text


async def test_importing_a_mismatched_key_is_rejected(client, auth):
    from decrypt0rx_core.pki import generate_root_ca

    one, two = generate_root_ca(common_name="A"), generate_root_ca(common_name="B")
    response = await client.post(
        "/api/v1/ca/import",
        json={"name": "Broken", "cert_pem": one.cert_pem, "key_pem": two.key_pem},
        headers=auth,
    )
    assert response.status_code == 422
    assert "does not match" in response.text


async def test_importing_a_valid_ca_round_trips(client, auth):
    from decrypt0rx_core.pki import generate_root_ca

    root = generate_root_ca(common_name="Corp Root", organization="Corp")
    response = await client.post(
        "/api/v1/ca/import",
        json={
            "name": "Corporate",
            "cert_pem": root.cert_pem,
            "key_pem": root.key_pem,
            "activate": True,
        },
        headers=auth,
    )
    assert response.status_code == 201, response.text
    assert response.json()["source"] == "imported"
    assert response.json()["fingerprint_sha256"] == root.fingerprint_sha256


async def test_the_stored_ca_key_is_encrypted_at_rest(client, auth):
    """The row must not contain PEM, and must decrypt with the master key."""
    await client.post("/api/v1/ca/generate", json={"name": "AtRest"}, headers=auth)

    from decrypt0rx_core.models import CertificateAuthority
    from sqlalchemy import select

    app = client.app
    async with app.state.session_factory() as session:
        ca = (await session.execute(select(CertificateAuthority))).scalars().first()

    assert "PRIVATE KEY" not in ca.key_encrypted
    assert ca.key_encrypted.startswith("v1:")
    recovered = app.state.secret_box.decrypt(
        ca.key_encrypted, aad=ca.fingerprint_sha256.encode()
    )
    assert b"BEGIN PRIVATE KEY" in recovered


# ----------------------------------------------------------------- policy


async def test_default_policies_are_seeded(client, auth):
    rules = (await client.get("/api/v1/policies", headers=auth)).json()
    assert len(rules) >= 2
    catch_all = rules[-1]
    assert catch_all["host_pattern"] == "*"
    assert catch_all["action"] == "intercept"
    # Opt-in capture is the whole point of the default: no bodies until asked.
    assert catch_all["capture_bodies"] is False


async def test_policy_crud_and_evaluation_order(client, auth):
    created = await client.post(
        "/api/v1/policies",
        json={
            "name": "Block ads",
            "priority": 5,
            "host_pattern": "*.ads.example",
            "action": "block",
        },
        headers=auth,
    )
    assert created.status_code == 201, created.text
    rule_id = created.json()["id"]

    verdict = (await client.post(
        "/api/v1/policies/test",
        json={"host": "tracker.ads.example", "port": 443},
        headers=auth,
    )).json()
    assert verdict["action"] == "block"
    assert verdict["matched_rule_id"] == rule_id

    # A host that matches nothing specific falls through to the catch-all.
    fallthrough = (await client.post(
        "/api/v1/policies/test", json={"host": "example.org"}, headers=auth
    )).json()
    assert fallthrough["action"] == "intercept"
    assert fallthrough["matched_rule_name"] == "Default: intercept, metadata only"

    patched = await client.patch(
        f"/api/v1/policies/{rule_id}", json={"enabled": False}, headers=auth
    )
    assert patched.json()["enabled"] is False
    after = (await client.post(
        "/api/v1/policies/test", json={"host": "tracker.ads.example"}, headers=auth
    )).json()
    assert after["action"] == "intercept"  # disabled rules are skipped

    assert (await client.delete(f"/api/v1/policies/{rule_id}", headers=auth)).status_code == 204


async def test_cidr_scoped_rule_only_matches_its_clients(client, auth):
    await client.post(
        "/api/v1/policies",
        json={
            "name": "Lab subnet bypass",
            "priority": 1,
            "host_pattern": "*",
            "client_cidr": "10.10.0.0/16",
            "action": "bypass",
        },
        headers=auth,
    )
    inside = (await client.post(
        "/api/v1/policies/test",
        json={"host": "anything.example", "client_ip": "10.10.4.9"},
        headers=auth,
    )).json()
    outside = (await client.post(
        "/api/v1/policies/test",
        json={"host": "anything.example", "client_ip": "192.168.1.5"},
        headers=auth,
    )).json()
    assert inside["action"] == "bypass"
    assert outside["action"] == "intercept"


async def test_invalid_cidr_is_rejected(client, auth):
    response = await client.post(
        "/api/v1/policies",
        json={"name": "Bad", "client_cidr": "not-a-cidr", "host_pattern": "*"},
        headers=auth,
    )
    assert response.status_code == 422


# ------------------------------------------------------------------- RBAC


async def test_viewers_cannot_change_policy_or_see_cas(client, auth):
    await client.post(
        "/api/v1/users",
        json={
            "email": "viewer@example.com",
            "password": "viewer-password-1234",
            "role": "viewer",
        },
        headers=auth,
    )
    token = (await client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@example.com", "password": "viewer-password-1234"},
    )).json()["access_token"]
    viewer = {"Authorization": f"Bearer {token}"}

    assert (await client.get("/api/v1/flows", headers=viewer)).status_code == 200
    assert (await client.get("/api/v1/policies", headers=viewer)).status_code == 403
    assert (await client.get("/api/v1/ca", headers=viewer)).status_code == 403
    assert (await client.get("/api/v1/users", headers=viewer)).status_code == 403


async def test_the_last_admin_cannot_be_demoted(client, auth):
    me = (await client.get("/api/v1/auth/me", headers=auth)).json()
    response = await client.patch(
        f"/api/v1/users/{me['id']}", json={"role": "viewer"}, headers=auth
    )
    assert response.status_code == 400
    assert "admin" in response.text.lower()


async def test_duplicate_users_are_rejected(client, auth):
    payload = {"email": "dup@example.com", "password": "some-long-password-1"}
    assert (await client.post("/api/v1/users", json=payload, headers=auth)).status_code == 201
    assert (await client.post("/api/v1/users", json=payload, headers=auth)).status_code == 409


# ------------------------------------------------------------------ flows


async def _insert_flows(app, count: int = 3):
    from decrypt0rx_core.models import Flow, PolicyAction

    async with app.state.session_factory() as session:
        for index in range(count):
            session.add(
                Flow(
                    id=uuid.uuid4(),
                    connection_id=uuid.uuid4(),
                    started_at=datetime.now(timezone.utc) - timedelta(seconds=index),
                    ended_at=datetime.now(timezone.utc),
                    duration_ms=12,
                    client_ip="10.0.0.5",
                    client_port=51000 + index,
                    host=f"host{index}.example",
                    port=443,
                    method="GET",
                    path=f"/page/{index}",
                    status_code=200 if index else 500,
                    request_headers={"Accept": "*/*"},
                    response_headers={"Content-Type": "text/html"},
                    request_size=10,
                    response_size=100,
                    action=PolicyAction.INTERCEPT,
                    intercepted=True,
                )
            )
        await session.commit()


async def test_flow_listing_filters_and_paginates(client, auth):
    await _insert_flows(client.app, 3)

    page = (await client.get("/api/v1/flows?limit=2", headers=auth)).json()
    assert page["total"] == 3
    assert len(page["items"]) == 2

    filtered = (await client.get("/api/v1/flows?host=host1", headers=auth)).json()
    assert filtered["total"] == 1
    assert filtered["items"][0]["path"] == "/page/1"

    by_status = (await client.get("/api/v1/flows?status_code=500", headers=auth)).json()
    assert by_status["total"] == 1


async def test_flow_detail_and_missing_body_message(client, auth):
    await _insert_flows(client.app, 1)
    flow_id = (await client.get("/api/v1/flows", headers=auth)).json()["items"][0]["id"]

    detail = (await client.get(f"/api/v1/flows/{flow_id}", headers=auth)).json()
    assert detail["has_request_body"] is False
    assert detail["request_headers"] == {"Accept": "*/*"}

    body = await client.get(f"/api/v1/flows/{flow_id}/body/response", headers=auth)
    assert body.status_code == 404
    assert "Enable body capture" in body.text


async def test_raw_dump_renders_the_transaction(client, auth):
    await _insert_flows(client.app, 1)
    flow_id = (await client.get("/api/v1/flows", headers=auth)).json()["items"][0]["id"]
    dump = await client.get(f"/api/v1/flows/{flow_id}/raw", headers=auth)
    assert dump.status_code == 200
    assert "GET /page/0" in dump.text
    assert "Content-Type: text/html" in dump.text


async def test_flow_stats_aggregate(client, auth):
    await _insert_flows(client.app, 3)
    stats = (await client.get("/api/v1/flows/stats?window_minutes=60", headers=auth)).json()
    assert stats["total"] == 3
    assert stats["intercepted"] == 3
    assert stats["bytes_out"] == 300
    assert {entry["host"] for entry in stats["top_hosts"]} == {
        "host0.example", "host1.example", "host2.example"
    }
    assert any(entry["bucket"] == 200 for entry in stats["status_breakdown"])


async def test_status_endpoint_reports_readiness(client, auth):
    before = (await client.get("/api/v1/status", headers=auth)).json()
    assert before["ca"] is None
    assert before["interception_ready"] is False

    await client.post("/api/v1/ca/generate", json={"name": "Ready"}, headers=auth)
    after = (await client.get("/api/v1/status", headers=auth)).json()
    assert after["ca"]["name"] == "Ready"
    assert after["enabled_rules"] >= 2


async def test_audit_log_records_mutations(client, auth):
    await client.post("/api/v1/ca/generate", json={"name": "Audited"}, headers=auth)
    entries = (await client.get("/api/v1/audit", headers=auth)).json()
    actions = {entry["action"] for entry in entries}
    assert "ca.generated" in actions
    assert "auth.login" in actions
