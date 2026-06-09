"""
tests/test_graphql_detector.py
────────────────────────────────────────────────────────────────────
Tests for proxy/modules/graphql_detector.py
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from proxy.core.interfaces import ProxyRequest, ProxyResponse
from proxy.modules.graphql_detector import (
    GraphQLDetector,
    _is_graphql_request,
    _parse_graphql_body,
)


# ─────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────

class FakeStore:
    async def write(self, t, r): pass
    async def read(self, t, i): return None
    async def query(self, t, f=None): return []
    async def subscribe(self, t, h): pass
    async def publish(self, t, p): pass


def _req(
    url="https://api.example.com/graphql",
    method="POST",
    headers=None,
    body=None,
):
    return ProxyRequest(
        id="test-req-id",
        timestamp=datetime.now(timezone.utc),
        method=method,
        url=url,
        headers=headers or {"content-type": "application/json"},
        body=body,
    )


def _gql_body(query, variables=None):
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    return json.dumps(payload).encode()


def _resp(status=200, body=None, headers=None):
    return ProxyResponse(
        request_id="test-req-id",
        timestamp=datetime.now(timezone.utc),
        status_code=status,
        headers=headers or {"content-type": "application/json"},
        body=json.dumps(body or {}).encode(),
    )


# ─────────────────────────────────────────────────────────────────
#  _parse_graphql_body
# ─────────────────────────────────────────────────────────────────

def test_parse_graphql_body_valid_json():
    req = _req(body=_gql_body("{ users { id } }"))
    result = _parse_graphql_body(req)
    assert result is not None
    assert result["query"] == "{ users { id } }"


def test_parse_graphql_body_no_body():
    req = _req(body=None)
    assert _parse_graphql_body(req) is None


def test_parse_graphql_body_non_json():
    req = _req(headers={"content-type": "text/plain"}, body=b"not json")
    assert _parse_graphql_body(req) is None


def test_parse_graphql_body_json_without_query():
    req = _req(body=json.dumps({"mutation": "test"}).encode())
    assert _parse_graphql_body(req) is None


# ─────────────────────────────────────────────────────────────────
#  _is_graphql_request
# ─────────────────────────────────────────────────────────────────

def test_is_graphql_by_path():
    req = _req(url="https://api.example.com/graphql", body=None)
    assert _is_graphql_request(req, None) is True


def test_is_graphql_by_path_case_insensitive():
    req = _req(url="https://api.example.com/GraphQL", body=None)
    assert _is_graphql_request(req, None) is True


def test_is_graphql_by_content_type():
    req = _req(
        url="https://api.example.com/api",
        headers={"content-type": "application/graphql"},
        body=b"{ users { id } }",
    )
    assert _is_graphql_request(req, None) is True


def test_is_graphql_by_body():
    req = _req(url="https://api.example.com/api", body=_gql_body("{ users { id } }"))
    gql = _parse_graphql_body(req)
    assert _is_graphql_request(req, gql) is True


def test_is_not_graphql_plain_post():
    req = _req(url="https://api.example.com/users", body=json.dumps({"name": "test"}).encode())
    gql = _parse_graphql_body(req)
    assert _is_graphql_request(req, gql) is False


# ─────────────────────────────────────────────────────────────────
#  on_request -- endpoint discovery
# ─────────────────────────────────────────────────────────────────

async def test_endpoint_discovery_first_request():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(body=_gql_body("{ users { id } }"))
    findings = await detector.on_request(req)
    discovery = [f for f in findings if f.title == "GraphQL endpoint discovered"]
    assert len(discovery) == 1
    assert discovery[0].severity == "info"


async def test_endpoint_discovery_deduped():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(body=_gql_body("{ users { id } }"))
    await detector.on_request(req)
    findings2 = await detector.on_request(req)
    discovery = [f for f in findings2 if f.title == "GraphQL endpoint discovered"]
    assert len(discovery) == 0


async def test_non_graphql_request_no_findings():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(url="https://api.example.com/users", body=json.dumps({"name": "test"}).encode())
    findings = await detector.on_request(req)
    assert findings == []


# ─────────────────────────────────────────────────────────────────
#  on_request -- introspection detection
# ─────────────────────────────────────────────────────────────────

async def test_introspection_schema_detected():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(body=_gql_body("{ __schema { types { name } } }"))
    findings = await detector.on_request(req)
    hits = [f for f in findings if "introspection" in f.title.lower()]
    assert len(hits) == 1
    assert hits[0].severity == "high"


async def test_introspection_type_detected():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(body=_gql_body('{ __type(name: "User") { fields { name } } }'))
    findings = await detector.on_request(req)
    assert any("introspection" in f.title.lower() for f in findings)


async def test_introspection_query_keyword_detected():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(body=_gql_body("query IntrospectionQuery { __schema { types { name } } }"))
    findings = await detector.on_request(req)
    assert any("introspection" in f.title.lower() for f in findings)


async def test_regular_query_no_introspection_finding():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(body=_gql_body("query { users { id name email } }"))
    findings = await detector.on_request(req)
    assert not any("introspection" in f.title.lower() for f in findings)


# ─────────────────────────────────────────────────────────────────
#  on_request -- mutation without auth
# ─────────────────────────────────────────────────────────────────

async def test_mutation_without_auth_flagged():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(
        body=_gql_body('mutation { createUser(name: "test") { id } }'),
        headers={"content-type": "application/json"},
    )
    findings = await detector.on_request(req)
    mutations = [f for f in findings if "mutation" in f.title.lower()]
    assert len(mutations) == 1
    assert mutations[0].severity == "medium"


async def test_mutation_with_auth_header_not_flagged():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(
        body=_gql_body('mutation { createUser(name: "test") { id } }'),
        headers={"content-type": "application/json", "Authorization": "Bearer token123"},
    )
    findings = await detector.on_request(req)
    assert not any("mutation" in f.title.lower() for f in findings)


async def test_mutation_with_cookie_not_flagged():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(
        body=_gql_body("mutation { deleteUser(id: 1) { success } }"),
        headers={"content-type": "application/json", "Cookie": "session=abc123"},
    )
    findings = await detector.on_request(req)
    assert not any("mutation" in f.title.lower() for f in findings)


async def test_regular_query_not_flagged_as_mutation():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(body=_gql_body("query { users { id } }"))
    findings = await detector.on_request(req)
    assert not any("mutation" in f.title.lower() for f in findings)


# ─────────────────────────────────────────────────────────────────
#  on_response -- confirmed endpoint and errors
# ─────────────────────────────────────────────────────────────────

async def test_confirmed_endpoint_on_data_response():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(body=_gql_body("{ users { id } }"))
    resp = _resp(status=200, body={"data": {"users": []}})
    findings = await detector.on_response(req, resp)
    confirmed = [f for f in findings if "confirmed" in f.title.lower()]
    assert len(confirmed) == 1
    assert confirmed[0].severity == "low"


async def test_confirmed_endpoint_on_errors_response():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(body=_gql_body("{ users { id } }"))
    resp = _resp(status=200, body={"errors": [{"message": "Not found"}]})
    findings = await detector.on_response(req, resp)
    confirmed = [f for f in findings if "confirmed" in f.title.lower()]
    assert len(confirmed) == 1


async def test_graphql_errors_flagged():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(body=_gql_body("{ users { id } }"))
    resp = _resp(
        status=200,
        body={"errors": [{"message": "Field 'secret' doesn't exist on type 'User'"}]},
    )
    findings = await detector.on_response(req, resp)
    errors = [f for f in findings if "errors in response" in f.title.lower()]
    assert len(errors) == 1
    assert errors[0].severity == "medium"
    assert errors[0].evidence["error_count"] == 1


async def test_non_graphql_response_no_findings():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(url="https://api.example.com/users", body=json.dumps({"name": "test"}).encode())
    resp = _resp(status=200, body={"id": 1, "name": "test"})
    findings = await detector.on_response(req, resp)
    assert findings == []


# ─────────────────────────────────────────────────────────────────
#  Healthcheck
# ─────────────────────────────────────────────────────────────────

async def test_healthcheck():
    store = FakeStore()
    detector = GraphQLDetector(store)
    req = _req(body=_gql_body("{ users { id } }"))
    await detector.on_request(req)
    health = await detector.healthcheck()
    assert health.status == "ok"
    assert health.module_name == "graphql_detector"
    assert "1 GraphQL endpoint(s)" in health.detail