"""Browser-facing /api: open access, scoping, sanitised audit, structured target."""

from datetime import datetime, timezone
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api import app
from app.investigations.models import InvestigationRecord, InvestigationStatus
from app.security.api_keys import APIKeyPrincipal
from app.security.dependencies import get_demo_principal
from app.tools.explicit_target import ExplicitTarget, compose_question
from app.tools.investigation_scope import (
    InvestigationScopeCreationError,
    create_bound_investigation_context,
)
from app.tools.workload_target import TargetQuestionError
from app.web.models import sanitize_audit_row, summarize_findings

NS = "ai-ops-demo"
PRINCIPAL = APIKeyPrincipal(principal_id="demo", allowed_namespaces=frozenset({NS}))


@pytest.fixture
def client():
    app.dependency_overrides[get_demo_principal] = lambda: PRINCIPAL
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_demo_principal, None)


def sign_in(client):
    return {"allowed_namespaces": [NS]}


def csrf(info):
    return {}


def row(status="completed", **extra):
    now = datetime.now(timezone.utc)
    base = {
        "investigation_id": str(uuid4()),
        "authorized_namespace": NS,
        "status": status,
        "created_at": now,
        "started_at": None if status == "pending" else now,
        "finished_at": now if status in {"completed", "failed"} else None,
        "stop_reason": None,
        "user_text": "Investigate deployment/bad-readiness. Why is it unhealthy?",
        "max_steps": 6,
        "findings": [
            {"title": "Pod discovered", "severity": "info"},
            {"title": "Container is running but not ready", "severity": "critical"},
        ],
    }
    base.update(extra)

    return base


def test_access_lists_demo_namespaces_without_credentials(client):
    response = client.get("/api/access")

    assert response.status_code == 200
    assert response.json() == {"allowed_namespaces": [NS]}


# ----------------------------------------------------------- scoped read APIs


def test_list_is_scoped_to_the_session_principals_namespaces(client):
    sign_in(client)
    repository = Mock()
    repository.list_investigations.return_value = ([row()], 1)

    with patch("app.web.routes.InvestigationRepository", return_value=repository):
        response = client.get("/api/investigations?limit=5&offset=0")

    assert response.status_code == 200
    kwargs = repository.list_investigations.call_args.kwargs
    assert kwargs["allowed_namespaces"] == frozenset({NS})
    assert kwargs["limit"] == 5
    item = response.json()["items"][0]
    assert item["scope"] == {"mode": "workload", "kind": "Deployment", "name": "bad-readiness"}
    assert item["primary_finding"] == {
        "title": "Container is running but not ready", "severity": "critical"
    }
    assert item["finding_counts"]["critical"] == 1


def test_list_page_size_is_bounded(client):
    sign_in(client)

    assert client.get("/api/investigations?limit=500").status_code == 422
    assert client.get("/api/investigations?offset=-1").status_code == 422


def test_pending_summary_has_no_findings_and_unknown_investigation_is_404(client):
    sign_in(client)
    repository = Mock()
    repository.get_investigation_row_for_namespaces.side_effect = [row("pending"), None]

    with patch("app.web.routes.InvestigationRepository", return_value=repository):
        pending = client.get(f"/api/investigations/{uuid4()}/summary")
        missing = client.get(f"/api/investigations/{uuid4()}/summary")

    assert pending.json()["primary_finding"] is None and pending.json()["finding_counts"] is None
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Investigation not found."}


def test_stats_come_from_the_repository_for_the_principals_namespaces(client):
    sign_in(client)
    repository = Mock()
    stats = {
        "total": 3, "completed": 2, "failed": 1, "in_progress": 0,
        "completed_with_warning_or_higher": 2, "average_duration_seconds": 7.5,
    }
    repository.investigation_stats.return_value = stats

    with patch("app.web.routes.InvestigationRepository", return_value=repository):
        response = client.get("/api/investigations/stats")

    assert response.json() == stats
    assert repository.investigation_stats.call_args.kwargs["allowed_namespaces"] == frozenset({NS})


def test_repository_errors_are_not_echoed(client):
    sign_in(client)
    repository = Mock()
    repository.investigation_stats.side_effect = RuntimeError("postgres://user:secret@db/x")

    with patch("app.web.routes.InvestigationRepository", return_value=repository):
        response = client.get("/api/investigations/stats")

    assert response.status_code == 500 and "secret" not in response.text


# ------------------------------------------------------------------- audit


def test_audit_requires_namespace_authorization_before_reading_events(client):
    sign_in(client)
    repository = Mock()
    repository.get_investigation_row_for_namespaces.return_value = None

    with patch("app.web.routes.InvestigationRepository", return_value=repository):
        response = client.get(f"/api/investigations/{uuid4()}/audit")

    assert response.status_code == 404
    repository.list_audit_events.assert_not_called()


def test_audit_view_is_sanitised():
    now = datetime.now(timezone.utc)
    clean = sanitize_audit_row({
        "event_id": uuid4(), "request_id": "run-1-step-1", "tool_call_id": None,
        "event_type": "rejected", "tool_name": "k8s.get_logs",
        "arguments": {"namespace": NS, "pod": "p-1", "token": "SECRET", "tail_lines": 50,
                      "container": "bad name; drop"},
        "status": "denied", "detail": "target_mismatch", "created_at": now,
    })

    assert clean.arguments == {"namespace": NS, "pod": "p-1", "tail_lines": 50}
    assert clean.reason_code == "target_mismatch"

    free_text = sanitize_audit_row({
        "event_id": uuid4(), "request_id": None, "tool_call_id": None,
        "event_type": "completed", "tool_name": "k8s.get_pods", "arguments": {},
        "status": "ok", "detail": "ApiException: HTTP 403 token=abc", "created_at": now,
    })

    assert free_text.reason_code is None
    assert sanitize_audit_row({"event_type": "weird", "event_id": uuid4(), "created_at": now}) is None


def test_audit_endpoint_returns_events_in_order_with_truncation_flag(client):
    sign_in(client)
    now = datetime.now(timezone.utc)
    events = [
        {"event_id": uuid4(), "request_id": "r", "tool_call_id": None, "event_type": t,
         "tool_name": "k8s.get_pods", "arguments": {"namespace": NS}, "status": "ok",
         "detail": None, "created_at": now}
        for t in ("proposed", "authorized", "execution_started", "completed")
    ]
    repository = Mock()
    repository.get_investigation_row_for_namespaces.return_value = row()
    repository.list_audit_events.return_value = (events, True)

    with patch("app.web.routes.InvestigationRepository", return_value=repository):
        body = client.get(f"/api/investigations/{uuid4()}/audit").json()

    assert [e["event_type"] for e in body["events"]] == [
        "proposed", "authorized", "execution_started", "completed"
    ]
    assert body["truncated"] is True


# ---------------------------------------------------------- findings summary


def test_summary_picks_the_highest_severity_finding_and_ignores_malformed_items():
    primary, counts = summarize_findings([
        {"title": "a", "severity": "info"},
        "junk",
        {"title": "b", "severity": "warning"},
        {"title": "c", "severity": "critical"},
        {"title": "d", "severity": "critical"},
        {"title": 5, "severity": "critical"},
    ])

    assert primary.title == "c" and counts.critical == 2 and counts.warning == 1 and counts.info == 1
    assert summarize_findings(None) == (None, None)


# ------------------------------------------------------ create / execute / target


def make_record(user_text, status=InvestigationStatus.PENDING):
    return InvestigationRecord(
        investigation_id=str(uuid4()), authorized_namespace=NS, status=status,
        created_at=datetime.now(timezone.utc), user_text=user_text, max_steps=6,
    )


def create(client, info, body):
    created = []

    class Repo:
        def create_investigation(self, *, investigation_id, authorized_namespace, user_text, max_steps):
            created.append(user_text)
            return make_record(user_text)

    with patch("app.api.InvestigationRepository", Repo):
        response = client.post("/api/investigations", json=body, headers=csrf(info))

    return response, created


def test_create_through_the_session_binds_the_structured_target(client):
    info = sign_in(client)
    response, created = create(client, info, {
        "namespace": NS, "question": "Why is this workload unhealthy?",
        "target": {"kind": "Deployment", "name": "bad-readiness"},
    })

    assert response.status_code == 201
    assert created == ["Investigate deployment/bad-readiness. Why is this workload unhealthy?"]


def test_create_rejects_a_namespace_outside_the_demo_list(client):
    info = sign_in(client)
    body = {"namespace": NS, "question": "Investigate the health of the namespace"}
    denied, created = create(client, info, {**body, "namespace": "kube-system"})

    assert denied.status_code == 403 and created == []


@pytest.mark.parametrize(
    "extra, code",
    [
        ({"question": "Also check payments-api", "target": {"kind": "Deployment", "name": "bad-readiness"}},
         "multiple_targets"),
        ({"question": "and everything else", "target": {"kind": "Deployment", "name": "bad-readiness"}},
         "ambiguous_scope"),
        ({"question": "Why failing?", "target": {"kind": "Deployment", "name": "app"}},
         "target_not_bindable"),
        ({"question": "Why failing?", "namespace_wide": True,
          "target": {"kind": "Deployment", "name": "bad-readiness"}}, None),
    ],
)
def test_ambiguous_or_unbindable_targets_fail_closed(client, extra, code):
    info = sign_in(client)
    response, created = create(client, info, {"namespace": NS, **extra})

    assert response.status_code == 422 and created == []

    if code:
        from app.tools.investigation_scope import SCOPE_REJECTION_MESSAGES
        assert response.json()["detail"] == SCOPE_REJECTION_MESSAGES[code]


def test_unsupported_kind_and_invalid_names_are_validation_errors(client):
    info = sign_in(client)

    for target in (
        {"kind": "Secret", "name": "x-y"},
        {"kind": "Deployment", "name": "Bad_Name"},
        {"kind": "Deployment", "name": "a" * 64},
        {"kind": "Deployment", "name": "ok-name", "extra": 1},
    ):
        response, created = create(client, info, {"namespace": NS, "question": "Why?", "target": target})

        assert response.status_code == 422 and created == []


def test_namespace_wide_is_explicit_and_never_a_fallback():
    assert compose_question("Anything wrong?", namespace=NS, target=None, namespace_wide=True) == (
        "Investigate the health of the whole namespace. Anything wrong?"
    )
    # A question with no scope at all is still refused (legacy behaviour).
    with pytest.raises(InvestigationScopeCreationError) as caught:
        create_bound_investigation_context("Is something wrong?", namespace=NS)

    assert caught.value.code == "scope_unspecified"


def test_namespace_wide_with_a_named_workload_is_refused():
    question = compose_question(
        "Why is payments-api failing?", namespace=NS, target=None, namespace_wide=True
    )

    with pytest.raises(InvestigationScopeCreationError) as caught:
        create_bound_investigation_context(question, namespace=NS)

    assert caught.value.code == "ambiguous_scope"


def test_target_is_never_widened_and_questions_without_structure_are_unchanged():
    assert compose_question("Why is x-1 failing?", namespace=NS, target=None, namespace_wide=False) == (
        "Why is x-1 failing?"
    )
    with pytest.raises(TargetQuestionError) as caught:
        compose_question(
            "Why?", namespace=NS, target=ExplicitTarget(kind="Pod", name="app"), namespace_wide=False
        )

    assert caught.value.code == "target_not_bindable"

    context = create_bound_investigation_context(
        compose_question(
            "Why?", namespace=NS,
            target=ExplicitTarget(kind="StatefulSet", name="db-0"), namespace_wide=False,
        ),
        namespace=NS,
    )

    assert context.target.name == "db-0" and context.broad_scope_explicit is False


def test_investigation_lookup_does_not_require_a_key(client):
    repository = Mock()
    repository.get_investigation_for_namespaces.return_value = None

    with patch("app.api.InvestigationRepository", return_value=repository):
        response = client.get(f"/investigations/{uuid4()}")

    assert response.status_code == 404
    assert repository.get_investigation_for_namespaces.call_args.kwargs["allowed_namespaces"] == frozenset({NS})


def test_execute_through_the_session_reaches_the_same_handler(client):
    info = sign_in(client)
    repository = Mock()
    repository.get_investigation_for_namespaces.return_value = None

    with patch("app.api.InvestigationRepository", return_value=repository):
        response = client.post(f"/api/investigations/{uuid4()}/execute", headers=csrf(info))

    assert response.status_code == 404
    assert repository.get_investigation_for_namespaces.call_args.kwargs["allowed_namespaces"] == frozenset({NS})


def test_frontend_scope_messages_mirror_backend_messages() -> None:
    """The browser shows a 422 only if it exactly matches a known message."""
    from pathlib import Path

    from app.tools.investigation_scope import SCOPE_REJECTION_MESSAGES

    source = Path("frontend/src/api/scopeMessages.ts").read_text(encoding="utf-8")
    for code, message in SCOPE_REJECTION_MESSAGES.items():
        assert code in source, code
        assert message in source, message
