from unittest.mock import MagicMock, patch
from uuid import UUID

import pytest

from app.audit import write_ask_audit


REQUEST_ID = UUID(
    "12345678-1234-5678-1234-567812345678"
)

def mock_connection():
    cursor = MagicMock()

    cursor_context = MagicMock()
    cursor_context.__enter__.return_value = cursor

    connection = MagicMock()
    connection.cursor.return_value = cursor_context

    connection_context = MagicMock()
    connection_context.__enter__.return_value = connection

    return connection_context, connection, cursor


@patch("app.audit.psycopg.connect")
def test_write_answered_audit(mock_connect):
    context, connection, cursor = mock_connection()
    mock_connect.return_value = context

    write_ask_audit(
        request_id=REQUEST_ID,
        question="What does red health mean?",
        status="answered",
        answer="A primary shard is unassigned.",
        sufficient=True,
        source_labels=[
            "runbook.pdf#page-6-chunk-12",
        ],
        model="Qwen/Qwen3-4B",
        retrieval_ms=12.5,
        sufficiency_ms=25.0,
        generation_ms=100.5,
        total_ms=138.0,
    )

    mock_connect.assert_called_once()

    sql, params = cursor.execute.call_args.args

    assert "INSERT INTO ask_audit" in sql
    assert params[0] == str(REQUEST_ID)
    assert params[1] == "What does red health mean?"
    assert params[2] == "answered"
    assert params[3] == "A primary shard is unassigned."
    assert params[4] is True
    assert params[5] == (
        '["runbook.pdf#page-6-chunk-12"]'
    )
    assert params[6] == "Qwen/Qwen3-4B"
    assert params[7] is None
    assert params[8] == 12.5
    assert params[9] == 25.0
    assert params[10] == 100.5
    assert params[11] == 138.0

    connection.commit.assert_called_once()


@patch("app.audit.psycopg.connect")
def test_write_insufficient_audit(mock_connect):
    context, connection, cursor = mock_connection()
    mock_connect.return_value = context

    write_ask_audit(
        request_id=REQUEST_ID,
        question="What is the production RTO?",
        status="insufficient_evidence",
        answer=(
            "I don't have sufficient evidence in the "
            "retrieved sources to answer this question."
        ),
        sufficient=False,
        source_labels=[],
        model="Qwen/Qwen3-4B",
        retrieval_ms=10.0,
        sufficiency_ms=20.0,
        generation_ms=None,
        total_ms=30.0,             
    )

    _, params = cursor.execute.call_args.args

    assert params[2] == "insufficient_evidence"
    assert params[4] is False
    assert params[5] == "[]"
    assert params[8] == 10.0
    assert params[9] == 20.0
    assert params[10] is None
    assert params[11] == 30.0
    
    connection.commit.assert_called_once()


@patch(
    "app.audit.psycopg.connect",
    side_effect=RuntimeError("database unavailable"),
)
def test_audit_failure_propagates(mock_connect):
    with pytest.raises(
        RuntimeError,
        match="database unavailable",
    ):
        write_ask_audit(
            request_id=REQUEST_ID,
            question="test",
            status="answered",
            answer="test answer",
            sufficient=True,
            source_labels=[],
            model="Qwen/Qwen3-4B",
        )
