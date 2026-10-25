"""Offline smoke-script tests using a mocked HTTP transport.

Never contacts the API server, Kubernetes, vLLM, or PostgreSQL.
"""

import json

import httpx
import pytest

from scripts import smoke_investigation as smoke

NAMESPACE = "demo"
INV_ID = "inv-123"
SECRET_KEY = "super-secret-api-key"
PRIVATE_LOG_LINE = "RAW-LOG-LINE-MUST-NOT-APPEAR"


def good_report(**overrides):
    report = {
        "investigation_id": INV_ID,
        "summary": "Established observations.",
        "findings": [
            {
                "title": "Pod identified",
                "description": "d",
                "severity": "info",
                "evidence": [{"evidence_id": "ev-0001"}],
            }
        ],
        "uncertainties": ["Log retrieval was bounded."],
        "suggested_checks": ["Inspect configuration."],
    }
    report.update(overrides)
    return report


def record(status, **overrides):
    body = {
        "investigation_id": INV_ID,
        "authorized_namespace": NAMESPACE,
        "status": status,
        "stop_reason": None if status == "pending" else "provider_finished",
        "user_text": "q",
        "max_steps": 3,
    }
    body.update(overrides)
    return body


def make_transport(*, create=None, execute=None, status=None, report=None, seen=None):
    routes = {
        ("POST", "/investigations"): create or (201, record("pending")),
        ("POST", f"/investigations/{INV_ID}/execute"): execute
        or (200, record("completed")),
        ("GET", f"/investigations/{INV_ID}"): status or (200, record("completed")),
        ("GET", f"/investigations/{INV_ID}/report"): report or (200, good_report()),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)

        code, body = routes[(request.method, request.url.path)]
        return httpx.Response(code, json=body)

    return httpx.MockTransport(handler)


def run(transport, **kwargs):
    outputs = []
    params = dict(
        namespace=NAMESPACE,
        live=True,
        base_url="http://api.test",
        api_key=SECRET_KEY,
        transport=transport,
        out=outputs.append,
    )
    params.update(kwargs)
    return smoke.run_smoke(**params), outputs


def test_live_opt_in_required():
    with pytest.raises(ValueError, match="--live"):
        smoke.run_smoke(namespace=NAMESPACE, live=False, api_key="k")


@pytest.mark.parametrize("namespace", ["", "Bad_NS", "a/b", "-x"])
def test_invalid_namespace_rejected(namespace):
    with pytest.raises(ValueError, match="[Nn]amespace"):
        smoke.run_smoke(namespace=namespace, live=True, api_key="k")


@pytest.mark.parametrize("max_steps", [0, 11])
def test_invalid_max_steps_rejected(max_steps):
    with pytest.raises(ValueError, match="max-steps"):
        smoke.run_smoke(
            namespace=NAMESPACE, live=True, api_key="k", max_steps=max_steps
        )


def test_full_lifecycle_uses_production_api_path():
    seen = []

    code, outputs = run(make_transport(seen=seen), max_steps=4)

    assert code == 0
    assert [(r.method, r.url.path) for r in seen] == [
        ("POST", "/investigations"),
        ("POST", f"/investigations/{INV_ID}/execute"),
        ("GET", f"/investigations/{INV_ID}"),
        ("GET", f"/investigations/{INV_ID}/report"),
    ]
    assert all("x-api-key" not in {name.lower() for name in r.headers} for r in seen)

    created = json.loads(seen[0].content)
    assert created["max_steps"] == 4
    # Scope travels as a structured field, not inside the question text.
    assert created["namespace"] == NAMESPACE
    assert "namespace" not in created["question"]

    assert "Smoke test passed." in outputs
    assert SECRET_KEY not in "\n".join(outputs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"create": (403, {"detail": "Namespace access denied."})},
        {"create": (201, record("pending", authorized_namespace="other"))},
        {"create": (201, record("running"))},
        {"execute": (409, {"detail": "Investigation is not pending."})},
        {"execute": (500, {"detail": "Investigation execution failed."})},
        {"execute": (200, record("failed", stop_reason="tool_failed"))},
        {"execute": (200, record("completed", user_text=None))},
        {"execute": (200, record("completed", investigation_id="other"))},
        {"status": (200, record("running"))},
        {"report": (404, {"detail": "Report not found."})},
        {"report": (200, good_report(investigation_id="other"))},
        {"report": (200, good_report(findings=[]))},
        {"report": (200, good_report(uncertainties=[]))},
        {"report": (200, good_report(summary="  "))},
        {"report": (200, {"unexpected": True})},
        {
            "report": (
                200,
                good_report(
                    findings=[
                        {
                            "title": "t",
                            "description": "d",
                            "severity": "info",
                            "evidence": [{"evidence_id": "not-an-id"}],
                        }
                    ]
                ),
            )
        },
    ],
)
def test_failures_raise_smoke_failure(kwargs):
    with pytest.raises(smoke.SmokeFailure):
        run(make_transport(**kwargs))


def test_transport_errors_are_reported_without_details():
    def boom(request):
        raise httpx.ConnectError("connect failed to http://secret-host")

    with pytest.raises(smoke.SmokeFailure) as caught:
        run(httpx.MockTransport(boom))

    assert "ConnectError" in str(caught.value)
    assert "secret-host" not in str(caught.value)


def test_server_error_body_is_never_echoed():
    transport = make_transport(
        execute=(
            500,
            {"detail": "x" * 500, "logs": PRIVATE_LOG_LINE},
        )
    )

    with pytest.raises(smoke.SmokeFailure) as caught:
        run(transport)

    message = str(caught.value)
    assert PRIVATE_LOG_LINE not in message
    assert len(message) < 250


def test_main_returns_nonzero_without_live(monkeypatch, capsys):
    assert smoke.main(["--namespace", NAMESPACE]) == 1
    assert "--live" in capsys.readouterr().err


def test_main_returns_nonzero_on_smoke_failure(monkeypatch, capsys):
    def fail(**kwargs):
        raise smoke.SmokeFailure("boom")

    monkeypatch.setattr(smoke, "run_smoke", fail)

    assert smoke.main(["--live", "--namespace", NAMESPACE]) == 1
    assert "FAILED: boom" in capsys.readouterr().err


def test_main_hides_unexpected_exception_messages(monkeypatch, capsys):
    def fail(**kwargs):
        raise KeyError("secret-internal-value")

    monkeypatch.setattr(smoke, "run_smoke", fail)

    assert smoke.main(["--live", "--namespace", NAMESPACE]) == 1
    err = capsys.readouterr().err
    assert "KeyError" in err
    assert "secret-internal-value" not in err


def test_smoke_reports_ai_analysis_state_without_hypothesis_text():
    report = good_report(
        ai_hypotheses=[
            {
                "explanation": "SECRET-HYPOTHESIS-TEXT may explain restarts.",
                "possible_explanation": "SECRET-HYPOTHESIS-TEXT may explain restarts.",
                "not_yet_verified": "Not yet verified.",
                "evidence_refs": ["ev-0001"],
                "resource": {"namespace": NAMESPACE},
                "verification_check": "Review describe output.",
            }
        ],
        ai_analysis={"state": "generated", "message": "Unverified."},
    )

    code, outputs = run(make_transport(report=(200, report)))

    joined = "\n".join(outputs)
    assert code == 0
    assert "AI analysis: generated, 1 unverified hypothesis(es)." in joined
    assert "SECRET-HYPOTHESIS-TEXT" not in joined


def test_smoke_tolerates_reports_without_ai_sections():
    code, outputs = run(make_transport())

    assert code == 0
    assert "AI analysis: not present in this report." in outputs
