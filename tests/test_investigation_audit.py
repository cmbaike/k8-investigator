"""Database-independent regression tests for the durable audit adapter."""

from unittest.mock import MagicMock

import pytest

from app.tools.investigation_audit import write_investigation_audit_event
from app.tools.investigation_scope import InvestigationScopeCreationError, create_investigation_context
from app.tools.orchestrator import InvestigationAuditEvent


def event(**changes):
    values = dict(
        investigation_id="inv-001", request_id="req-001",
        phase="execution_started", tool="k8s.get_pods",
        arguments={"namespace": "ai-ops-demo", "password": "SECRET"},
        status="started", detail=None,
    )
    values.update(changes)
    return InvestigationAuditEvent(**values)


def test_writer_persists_event_and_redacts_unknown_arguments(monkeypatch):
    cursor = MagicMock()
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.cursor.return_value.__enter__.return_value = cursor
    connect = MagicMock(return_value=connection)
    monkeypatch.setenv("DATABASE_URL", "postgresql://test")
    monkeypatch.setattr("app.tools.investigation_audit.psycopg.connect", connect)

    write_investigation_audit_event(event())

    assert cursor.execute.call_count == 1
    sql, parameters = cursor.execute.call_args.args
    assert "investigation_audit_events" in sql
    assert parameters[1:4] == ("inv-001", "req-001", "execution_started")
    assert '"namespace": "ai-ops-demo"' in parameters[5]
    assert "SECRET" not in parameters[5]


def test_invalid_phase_never_connects(monkeypatch):
    connect = MagicMock()
    monkeypatch.setattr("app.tools.investigation_audit.psycopg.connect", connect)
    with pytest.raises(ValueError):
        write_investigation_audit_event(event(phase="unexpected"))
    connect.assert_not_called()


def test_database_failure_propagates(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://test")
    connect = MagicMock(side_effect=OSError("database down"))
    monkeypatch.setattr("app.tools.investigation_audit.psycopg.connect", connect)
    with pytest.raises(OSError, match="database down"):
        write_investigation_audit_event(event())
        
def test_context_creation_requires_investigation_intent():
    with pytest.raises(InvestigationScopeCreationError):
        create_investigation_context(
            "Show information about namespace ai-ops-demo."
        )          
