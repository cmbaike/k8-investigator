from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
import pytest

from app.api import app
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


def mock_connection_with_row(row):
    cursor = MagicMock()
    cursor.fetchone.return_value = row

    cursor_context = MagicMock()
    cursor_context.__enter__.return_value = cursor

    connection = MagicMock()
    connection.cursor.return_value = cursor_context

    connection_context = MagicMock()
    connection_context.__enter__.return_value = connection

    return connection_context, cursor


def mock_connection_with_rows(rows):
    cursor = MagicMock()
    cursor.fetchall.return_value = rows

    cursor_context = MagicMock()
    cursor_context.__enter__.return_value = cursor

    connection = MagicMock()
    connection.cursor.return_value = cursor_context

    connection_context = MagicMock()
    connection_context.__enter__.return_value = connection

    return connection_context, cursor


@patch("app.api.psycopg.connect")
def test_list_documents(mock_connect):
    created_at = datetime(
        2026, 10, 4, 8, 0,
        tzinfo=timezone.utc,
    )

    connection, _ = mock_connection_with_rows([
        (
            7,
            "runbook.pdf",
            "abc123",
            "application/pdf",
            23234,
            created_at,
            22,
            10,
        )
    ])
    mock_connect.return_value = connection

    response = client.get("/documents")

    assert response.status_code == 200

    body = response.json()

    assert len(body) == 1
    assert body[0]["id"] == 7
    assert body[0]["filename"] == "runbook.pdf"
    assert body[0]["sha256"] == "abc123"
    assert body[0]["status"] == "ready"
    assert body[0]["chunks"] == 22
    assert body[0]["pages"] == 10


@patch("app.api.psycopg.connect")
def test_get_document(mock_connect):
    created_at = datetime(
        2026, 10, 4, 8, 0,
        tzinfo=timezone.utc,
    )

    connection, _ = mock_connection_with_row(
        (
            7,
            "runbook.pdf",
            "abc123",
            "application/pdf",
            23234,
            created_at,
            22,
            10,
            1,
            10,
        )
    )
    mock_connect.return_value = connection

    response = client.get("/documents/7")

    assert response.status_code == 200

    body = response.json()

    assert body["id"] == 7
    assert body["status"] == "ready"
    assert body["chunks"] == 22
    assert body["pages"] == 10
    assert body["first_page"] == 1
    assert body["last_page"] == 10


@patch("app.api.psycopg.connect")
def test_get_document_not_found(mock_connect):
    connection, _ = mock_connection_with_row(None)
    mock_connect.return_value = connection

    response = client.get("/documents/999999")

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Document not found.",
    }


@patch("app.api.psycopg.connect")
def test_delete_document(mock_connect):
    connection, cursor = mock_connection_with_row(
        ("temporary.pdf",)
    )
    mock_connect.return_value = connection

    response = client.delete("/documents/123")

    assert response.status_code == 200
    assert response.json() == {
        "status": "deleted",
        "document_id": 123,
        "filename": "temporary.pdf",
    }

    connection.__enter__.return_value.commit.assert_called_once()
