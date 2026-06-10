"""
tests/test_graphql_detector.py
────────────────────────────────────────────────────────────────────
Tests for proxy/modules/graphql_detector.py
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from proxy.core.interfaces import ProxyRequest, ProxyResponse
from proxy.modules.graphql_detector import (
    GraphQLDetector,
    _is_graphql_request,
    _is_graphql_response,
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
    url: str = "https://api.example.com/graphql",
    method: str = "POST",
    headers: dict | None = None,
    body: bytes | None = None,
) -> ProxyRequest:
    return ProxyRequest(
        id="test-id",
        timestamp=datetime.now(timezone.utc),
        method=method,
        url=url,
        headers=headers or {"content-type": "application/json"},
        body=body,
    )


def _resp(
    body: bytes | None = None,
    headers: dict | None = None,
    status: int = 200,
) -> ProxyResponse:
    return ProxyResponse(
        request_id="test-id",
        timestamp=datetime.now(timezone.utc),
        status_code=status,
        headers=headers or {"content-type": "application/json"},
        body=body,
    )


def _gql_body(query: str) -> bytes:
    return json.dumps({"query": query}).encode()


# ─────────────────────────────────────────────────────────────────
#  _is_graphql_request
# ─────────────────────────────────────────────────────────────────

def test_detects_graphql_path():
    assert _is_graphql_request(_req(url="https://api.example.com/graphql")) is True

def test_detects_graphql_path_case_insensitive():
    assert _is_graphql_request(_req(url="https://api.example.com/GraphQL")) is True

def test_detects_nested_graphql_path():
    assert _is_graphql_request(_req(url="https://api.example.com/api/v1/graphql")) is True

def test_detects_application_graphql_content_type():
    req = _req(url="https://api.example.com/query",
               headers={"content-type": "application/graphql"},
               body=b"{ users { id } }")
    assert _is_graphql_request(req) is True

def test_detects_json_body_with_query_key():
    req = _req(url="https://api.example.com/data",
               body=_gql_body("{ users { id } }"))
    assert _is_graphql_request(req) is True

def test_ignores_json_without_query_key():
    req = _req(url="https://api.example.com/data",
               body=json.dumps({"name": "Alice"}).encode())
    assert _is_graphql_request(req) is False

def test_ignores_non_graphql_path():
    assert _is_graphql_request(_req(url="https://api.example.com/users")) is False

def test_detects_batched_query():
    body = json.dumps([{"query": "{ users { id } }"}, {"query": "{ products { id } }"}]).encode()
    assert _is_graphql_request(_req(body=body)) is True


# ─────────────────────────────────────────────────────────────────
#  _is_graphql_response
# ─────────────────────────────────────────────────────────────────

def test_detects_graphql_response_with_data():
    assert _is_graphql_response(_resp(body=b'{"data":{"users":[]}}')) is True

def test_detects_graphql_response_with_errors():
    assert _is_graphql_response(_resp(body=b'{"errors":[{"message":"Not found"}]}')) is True

def test_ignores_non_json_response():
    assert _is_graphql_response(_resp(body=b"<html></html>",
                                      headers={"content-type": "text/html"})) is False

def test_ignores_empty_response():
    assert _is_graphql_response(_resp(body=None)) is False


# ─────────────────────────────────────────────────────────────────
#  on_request — endpoint discovery
# ─────────────────────────────────────────────────────────────────

async def test_discovers_graphql_endpoint():
    detector = GraphQLDetector(FakeStore())
    findings = await detector.on_request(_req(body=_gql_body("{ users { id } }")))
    info = [f for f in findings if f.title == "GraphQL endpoint discovered"]
    assert len(info) == 1
    assert info[0].severity == "info"

async def test_endpoint_discovery_dedup_per_host():
    detector = GraphQLDetector(FakeStore())
    req = _req(body=_gql_body("{ users { id } }"))
    await detector.on_request(req)
    findings2 = await detector.on_request(req)
    assert [f for f in findings2 if f.title == "GraphQL endpoint discovered"] == []


# ─────────────────────────────────────────────────────────────────
#  on_request — introspection
# ─────────────────────────────────────────────────────────────────

async def test_flags_introspection_schema():
    detector = GraphQLDetector(FakeStore())
    findings = await detector.on_request(_req(body=_gql_body("{ __schema { types { name } } }")))
    intros = [f for f in findings if "introspection" in f.title.lower()]
    assert len(intros) == 1
    assert intros[0].severity == "high"

async def test_flags_introspection_type():
    detector = GraphQLDetector(FakeStore())
    findings = await detector.on_request(_req(body=_gql_body('{ __type(name: "User") { fields { name } } }')))
    assert any("introspection" in f.title.lower() for f in findings)

async def test_no_introspection_flag_on_normal_query():
    detector = GraphQLDetector(FakeStore())
    findings = await detector.on_request(_req(body=_gql_body("{ users { id name email } }")))
    assert not any("introspection" in f.title.lower() for f in findings)


# ─────────────────────────────────────────────────────────────────
#  on_request — mutation without auth
# ─────────────────────────────────────────────────────────────────

async def test_flags_mutation_without_auth():
    detector = GraphQLDetector(FakeStore())
    req = _req(headers={"content-type": "application/json"},
               body=_gql_body("mutation CreateUser { createUser(name: \"Alice\") { id } }"))
    findings = await detector.on_request(req)
    mutations = [f for f in findings if "mutation" in f.title.lower()]
    assert len(mutations) == 1
    assert mutations[0].severity == "medium"

async def test_no_mutation_flag_with_auth_header():
    detector = GraphQLDetector(FakeStore())
    req = _req(headers={"content-type": "application/json", "Authorization": "Bearer tok"},
               body=_gql_body("mutation DeleteUser { deleteUser(id: 1) }"))
    findings = await detector.on_request(req)
    assert not any("mutation" in f.title.lower() for f in findings)

async def test_no_mutation_flag_with_cookie():
    detector = GraphQLDetector(FakeStore())
    req = _req(headers={"content-type": "application/json", "Cookie": "session=abc"},
               body=_gql_body("mutation UpdateUser { updateUser(id: 1, name: \"Bob\") { id } }"))
    findings = await detector.on_request(req)
    assert not any("mutation" in f.title.lower() for f in findings)


# ─────────────────────────────────────────────────────────────────
#  on_request — batched queries
# ─────────────────────────────────────────────────────────────────

async def test_flags_batched_queries():
    detector = GraphQLDetector(FakeStore())
    body = json.dumps([{"query": "{ users { id } }"}, {"query": "{ products { id } }"},
                       {"query": "{ orders { id } }"}]).encode()
    findings = await detector.on_request(_req(body=body))
    batched = [f for f in findings if "batched" in f.title.lower()]
    assert len(batched) == 1
    assert batched[0].severity == "medium"
    assert batched[0].evidence["batch_size"] == 3

async def test_single_query_not_flagged_as_batch():
    detector = GraphQLDetector(FakeStore())
    findings = await detector.on_request(_req(body=_gql_body("{ users { id } }")))
    assert not any("batched" in f.title.lower() for f in findings)


# ─────────────────────────────────────────────────────────────────
#  on_response — errors
# ─────────────────────────────────────────────────────────────────

async def test_flags_graphql_errors_in_response():
    detector = GraphQLDetector(FakeStore())
    body = json.dumps({"errors": [
        {"message": "Field 'password' not found on type 'User'"},
        {"message": "Internal server error"},
    ]}).encode()
    findings = await detector.on_response(_req(), _resp(body=body))
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].evidence["error_count"] == 2

async def test_no_error_finding_on_successful_response():
    detector = GraphQLDetector(FakeStore())
    body = json.dumps({"data": {"users": [{"id": 1}]}}).encode()
    findings = await detector.on_response(_req(), _resp(body=body))
    assert findings == []

async def test_ignores_non_graphql_response():
    detector = GraphQLDetector(FakeStore())
    resp = _resp(body=b"<html>Error</html>", headers={"content-type": "text/html"})
    findings = await detector.on_response(_req(), resp)
    assert findings == []


# ─────────────────────────────────────────────────────────────────
#  Healthcheck
# ─────────────────────────────────────────────────────────────────

async def test_healthcheck():
    detector = GraphQLDetector(FakeStore())
    await detector.on_request(_req(body=_gql_body("{ users { id } }")))
    health = await detector.healthcheck()
    assert health.status == "ok"
    assert health.module_name == "graphql_detector"
    assert "1 GraphQL endpoint(s)" in health.detail