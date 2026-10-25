
from unittest.mock import patch

import pytest
from app.rag import VLLM_MODEL

from fastapi.testclient import TestClient

from app.api import (
    INSUFFICIENT_EVIDENCE_MESSAGE,
    app,
)
from app.security.api_keys import APIKeyPrincipal
from app.security.dependencies import require_api_key_principal

client = TestClient(app)

@pytest.fixture(autouse=True)
def authenticated_api_client():
    principal = APIKeyPrincipal(
        principal_id="api-test",
        allowed_namespaces=frozenset({"ai-ops-demo"}),
    )

    app.dependency_overrides[
        require_api_key_principal
    ] = lambda: principal

    try:
        yield
    finally:
        app.dependency_overrides.pop(
            require_api_key_principal,
            None,
        )
        
SOURCE = {
    "filename": "runbook.pdf",
    "chunk_index": 12,
    "page_number": 6,
    "content": (
        "Red means at least one primary shard is unassigned."
    ),
    "similarity": 0.91,
}


class Sufficient:
    sufficient = True


class Insufficient:
    sufficient = False


@patch("app.api.write_ask_audit")
@patch("app.api.generate_answer")
@patch("app.api.assess_typed_atomic_sufficiency")
@patch("app.api.retrieve_evidence")
def test_ask_answered_contract(
    mock_retrieve,
    mock_sufficiency,
    mock_generate,
    mock_write_audit,
):
    mock_retrieve.return_value = [SOURCE]
    mock_sufficiency.return_value = Sufficient()
    mock_generate.return_value = (
        "Red means at least one primary shard is unassigned. "
        "[SOURCE: runbook.pdf#page-6-chunk-12]"
    )

    response = client.post(
        "/ask",
        json={
            "question": (
                "What does red Elasticsearch health mean?"
            ),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["request_id"]
    assert body["status"] == "answered"
    assert body["sufficiency"] == {
        "sufficient": True,
    }

    assert body["question"] == (
        "What does red Elasticsearch health mean?"
    )

    assert len(body["sources"]) == 1

    source = body["sources"][0]

    assert source["label"] == (
        "runbook.pdf#page-6-chunk-12"
    )
    assert source["filename"] == "runbook.pdf"
    assert source["page_number"] == 6
    assert source["chunk_index"] == 12
    assert source["excerpt"] == SOURCE["content"]

    mock_generate.assert_called_once()
    mock_write_audit.assert_called_once()
    kwargs = mock_write_audit.call_args.kwargs
    
    assert kwargs["request_id"] == body["request_id"]
    assert kwargs["question"] == body["question"]
    assert kwargs["status"] == "answered"
    assert kwargs["answer"] == body["answer"]
    assert kwargs["sufficient"] is True
    assert kwargs["model"] == VLLM_MODEL
    assert kwargs["source_labels"]
    
    timings = body["timings"]

    assert timings["retrieval_ms"] >= 0
    assert timings["sufficiency_ms"] >= 0
    assert timings["generation_ms"] >= 0
    assert timings["total_ms"] >= 0

    assert timings["total_ms"] >= timings["retrieval_ms"]
    assert timings["total_ms"] >= timings["sufficiency_ms"]
    assert timings["total_ms"] >= timings["generation_ms"]
    
    assert kwargs["retrieval_ms"] == timings["retrieval_ms"]
    assert kwargs["sufficiency_ms"] == timings["sufficiency_ms"]
    assert kwargs["generation_ms"] == timings["generation_ms"]
    assert kwargs["total_ms"] == timings["total_ms"]  


@patch("app.api.write_ask_audit")
@patch("app.api.generate_answer")
@patch("app.api.assess_typed_atomic_sufficiency")
@patch("app.api.retrieve_evidence")
def test_ask_insufficient_evidence_contract(
    mock_retrieve,
    mock_sufficiency,
    mock_generate,
    mock_write_audit,
):
    mock_retrieve.return_value = [SOURCE]
    mock_sufficiency.return_value = Insufficient()

    response = client.post(
        "/ask",
        json={
            "question": "What is the production RTO?",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["request_id"]
    assert body["status"] == "insufficient_evidence"
    assert body["answer"] == INSUFFICIENT_EVIDENCE_MESSAGE
    assert body["sufficiency"] == {
        "sufficient": False,
    }

    # Retrieved evidence remains inspectable even when
    # the platform refuses to answer.
    assert len(body["sources"]) == 1
    assert body["sources"][0]["label"] == (
        "runbook.pdf#page-6-chunk-12"
    )

    # Insufficient evidence must never reach generation.
    mock_generate.assert_not_called()
    
    mock_write_audit.assert_called_once()

    kwargs = mock_write_audit.call_args.kwargs

    assert kwargs["request_id"] == body["request_id"]
    assert kwargs["status"] == "insufficient_evidence"
    assert kwargs["answer"] == INSUFFICIENT_EVIDENCE_MESSAGE
    assert kwargs["sufficient"] is False
    assert kwargs["model"] == VLLM_MODEL
    timings = body["timings"]

    assert timings["retrieval_ms"] >= 0
    assert timings["sufficiency_ms"] >= 0
    assert timings["generation_ms"] is None
    assert timings["total_ms"] >= 0

    assert kwargs["retrieval_ms"] == timings["retrieval_ms"]
    assert kwargs["sufficiency_ms"] == timings["sufficiency_ms"]
    assert kwargs["generation_ms"] is None
    assert kwargs["total_ms"] == timings["total_ms"]

@patch("app.api.write_ask_audit")
def test_ask_rejects_empty_question(mock_audit):
    response = client.post(
        "/ask",
        json={"question": ""},
    )

    assert response.status_code == 422
    mock_audit.assert_not_called()
    
    
@patch(
    "app.api.write_ask_audit",
    side_effect=RuntimeError("audit database unavailable"),
)
@patch("app.api.generate_answer")
@patch("app.api.assess_typed_atomic_sufficiency")
@patch("app.api.retrieve_evidence")
def test_ask_fails_if_audit_write_fails(
    mock_retrieve,
    mock_sufficiency,
    mock_generate,
    mock_audit,
):
    mock_retrieve.return_value = [
        {
            "filename": "runbook.pdf",
            "chunk_index": 12,
            "page_number": 6,
            "content": (
                "Red health means at least one "
                "primary shard is unassigned."
            ),
            "similarity": 0.9,
        }
    ]

    mock_sufficiency.return_value.sufficient = True
    mock_generate.return_value = (
        "At least one primary shard is unassigned."
    )

    response = client.post(
        "/ask",
        json={
            "question": "What does red health mean?",
        },
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": "audit database unavailable",
    }

    mock_generate.assert_called_once()
    mock_audit.assert_called_once()    
    
