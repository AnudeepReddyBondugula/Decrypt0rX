"""Pins the control plane's dry-run evaluator to the proxy's real engine.

`POST /policies/test` answers "what would the proxy do with this host?". It is
a second implementation of the matching logic in `PolicyEngine.evaluate`, and a
wrong answer is worse than no answer: an operator reads "bypass" and believes a
host is not being decrypted when it is.

Nothing but this test stops the two drifting. It lives under the API tests
because it needs both a real Postgres and the real engine.
"""

from __future__ import annotations

import base64

import pytest
from decrypt0rx_proxy.config import ProxySettings
from decrypt0rx_proxy.policy import PolicyEngine

pytestmark = pytest.mark.asyncio

MASTER_KEY = base64.b64encode(b"p" * 32).decode()

# A rule set chosen to exercise every condition the matcher supports, and to
# overlap so that priority ordering decides the outcome.
RULES = [
    {
        "name": "Block a single host",
        "priority": 5,
        "host_pattern": "ads.example.com",
        "action": "block",
    },
    {
        "name": "Bypass a wildcard",
        "priority": 10,
        "host_pattern": "*.bank.example",
        "action": "bypass",
    },
    {
        "name": "Capture from the lab subnet only",
        "priority": 20,
        "host_pattern": "*.internal.corp",
        "client_cidr": "10.10.0.0/16",
        "action": "intercept",
        "capture_bodies": True,
        "redact": False,
    },
    {
        "name": "Port-specific rule",
        "priority": 30,
        "host_pattern": "api.example.com",
        "port": 8443,
        "action": "bypass",
    },
    {
        "name": "Disabled rule that would otherwise match everything",
        "priority": 1,
        "host_pattern": "*",
        "action": "block",
        "enabled": False,
    },
    {
        "name": "Lower priority overlap, should never win",
        "priority": 900,
        "host_pattern": "ads.example.com",
        "action": "intercept",
    },
]

# (host, port, client_ip) — each probes a different branch of the matcher.
CASES = [
    ("ads.example.com", 443, "10.0.0.1"),        # exact match, highest priority wins
    ("ADS.EXAMPLE.COM", 443, "10.0.0.1"),        # host matching is case-insensitive
    ("login.bank.example", 443, "10.0.0.1"),     # wildcard match
    ("bank.example", 443, "10.0.0.1"),           # wildcard does NOT match the bare domain
    ("api.internal.corp", 443, "10.10.4.9"),     # inside the CIDR
    ("api.internal.corp", 443, "192.168.1.5"),   # outside the CIDR, falls through
    ("api.example.com", 8443, "10.0.0.1"),       # port matches
    ("api.example.com", 443, "10.0.0.1"),        # same host, wrong port, falls through
    ("unmatched.example.org", 443, "10.0.0.1"),  # only the seeded catch-all applies
    ("deep.sub.internal.corp", 443, "10.10.0.2"),
]


async def test_dry_run_evaluator_matches_the_proxy_engine(client, auth):
    for rule in RULES:
        response = await client.post("/api/v1/policies", json=rule, headers=auth)
        assert response.status_code == 201, response.text

    # The same rows the proxy would load, through the proxy's own engine.
    engine = PolicyEngine(ProxySettings(master_key=MASTER_KEY))
    await engine.refresh(client.app.state.session_factory)
    stored = (await client.get("/api/v1/policies", headers=auth)).json()
    assert engine.rule_count == len([r for r in stored if r["enabled"]])

    for host, port, client_ip in CASES:
        decision = engine.evaluate(host, port, client_ip)

        response = await client.post(
            "/api/v1/policies/test",
            json={"host": host, "port": port, "client_ip": client_ip},
            headers=auth,
        )
        assert response.status_code == 200, response.text
        verdict = response.json()

        context = f"{host}:{port} from {client_ip}"
        assert verdict["action"] == decision.action.value, (
            f"action disagrees for {context}: API says {verdict['action']!r}, "
            f"the proxy would do {decision.action.value!r}"
        )
        assert verdict["capture_bodies"] == decision.capture_bodies, (
            f"capture_bodies disagrees for {context}"
        )
        assert verdict["redact"] == decision.redact, f"redact disagrees for {context}"
        assert verdict["matched_rule_id"] == decision.rule_id, (
            f"matched rule disagrees for {context}: API matched "
            f"{verdict['matched_rule_name']!r}, proxy matched {decision.rule_name!r}"
        )


async def test_both_agree_when_no_rule_matches(client, auth):
    """With every rule gone, both sides must fall back the same way."""
    for rule in (await client.get("/api/v1/policies", headers=auth)).json():
        assert (
            await client.delete(f"/api/v1/policies/{rule['id']}", headers=auth)
        ).status_code == 204

    engine = PolicyEngine(ProxySettings(master_key=MASTER_KEY))
    await engine.refresh(client.app.state.session_factory)
    assert engine.rule_count == 0

    decision = engine.evaluate("anything.example", 443, "10.0.0.1")
    verdict = (
        await client.post(
            "/api/v1/policies/test", json={"host": "anything.example"}, headers=auth
        )
    ).json()

    assert verdict["action"] == decision.action.value == "intercept"
    assert verdict["capture_bodies"] == decision.capture_bodies is False
    assert verdict["redact"] == decision.redact is True
    assert verdict["matched_rule_id"] is None and decision.rule_id is None


async def test_the_parity_check_can_actually_fail(client, auth):
    """Guards the guard.

    A parity test that passes no matter what is worse than none, so prove the
    comparison has teeth: a rule the engine has not loaded yet must make the
    two sides disagree.
    """
    engine = PolicyEngine(ProxySettings(master_key=MASTER_KEY))
    await engine.refresh(client.app.state.session_factory)

    response = await client.post(
        "/api/v1/policies",
        json={
            "name": "Added after the snapshot",
            "priority": 1,
            "host_pattern": "late.example",
            "action": "block",
        },
        headers=auth,
    )
    assert response.status_code == 201

    stale = engine.evaluate("late.example", 443, "10.0.0.1")
    fresh = (
        await client.post(
            "/api/v1/policies/test", json={"host": "late.example"}, headers=auth
        )
    ).json()

    assert stale.action.value == "intercept"   # the snapshot predates the rule
    assert fresh["action"] == "block"          # the database has it

    # And once the proxy refreshes, they agree again - which is the whole
    # contract between the two implementations.
    await engine.refresh(client.app.state.session_factory)
    assert engine.evaluate("late.example", 443, "10.0.0.1").action.value == "block"
