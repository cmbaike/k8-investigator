"""CLI viewer: rendering, API failure handling, auth and terminal safety.

No network: the API is an in-process httpx MockTransport. Reports are produced
by the real engine (grounding + hypothesis validation), so these tests cover
the actual API contract, not hand-written approximations of it.
"""

import io
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.investigations.models import InvestigationRecord
from app.reports.grounding import build_grounded_report
from scripts import demo_investigation as demo
from tests.test_diagnostic_correlation import (
    ENV,
    LOG_LINES,
    NS,
    POD,
    SENTINEL,
    build_context,
    enrich,
    full_refs,
    model_hypothesis,
    provider_returning,
    snap,
)

KEY = "demo-key-DO-NOT-PRINT-7731"
ID = str(uuid.uuid4())
QUESTION = "Investigate why the billing service is failing in namespace team-a."
NOW = datetime(2026, 10, 15, 20, 0, tzinfo=timezone.utc)


def record_payload(status="completed", **over):
    payload = {
        "investigation_id": ID,
        "authorized_namespace": NS,
        "status": status,
        "created_at": NOW.isoformat(),
        "started_at": NOW.isoformat(),
        "finished_at": (NOW + timedelta(seconds=3.1)).isoformat(),
        "stop_reason": "provider_finished",
        "user_text": QUESTION,
        "max_steps": 6,
    }
    payload.update(over)
    return payload


def make_report(*, hypotheses=True, ctx_kwargs=None, provider=None):
    ctx = build_context(investigation_id=ID, **(ctx_kwargs or {}))
    refs = full_refs(snap(ctx))
    if provider is None:
        items = [model_hypothesis(evidence=refs)] if hypotheses else []
        provider = provider_returning(*items, investigation_id=ID)
    _, report = enrich(ctx, provider)
    return report


@pytest.fixture(scope="module")
def report():
    return make_report()


@pytest.fixture(scope="module")
def payload(report):
    return report.model_dump(mode="json")


class Server:
    """Records requests and answers from a route table."""

    def __init__(self, routes):
        self.routes = routes
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        route = self.routes.get((request.method, request.url.path))
        if route is None:
            return httpx.Response(404, json={"detail": "Investigation not found."})
        if isinstance(route, Exception):
            raise route
        if callable(route):
            return route(request)
        status, body = route
        return httpx.Response(status, json=body)

    @property
    def paths(self):
        return [(r.method, r.url.path) for r in self.requests]


def run(argv, server=None, *, env=None, sleep=lambda _s: None):
    out, err = io.StringIO(), io.StringIO()
    transport = httpx.MockTransport(server) if server is not None else None
    code = demo.main(
        argv,
        env={demo.API_KEY_ENV: KEY} if env is None else env,
        out=out,
        err=err,
        transport=transport,
        sleep=sleep,
    )
    return code, out.getvalue(), err.getvalue()


def view(server, *extra):
    return run(["--investigation-id", ID, "--color", "never", *extra], server)


def completed_server(payload, **record_over):
    return Server(
        {
            ("GET", f"/investigations/{ID}"): (200, record_payload(**record_over)),
            ("GET", f"/investigations/{ID}/report"): (200, payload),
        }
    )


def section_positions(text):
    marks = [
        "1. INVESTIGATION",
        "2. HIGH-PRIORITY VERIFIED FINDINGS",
        "3. RELEVANT KUBERNETES SYMPTOMS",
        "4. VERIFIED WORKLOAD CONFIGURATION",
        "5. AI DIAGNOSTIC HYPOTHESES",
        "6. APPLICATION-WRITTEN CONFIGURATION CONTEXT",
        "7. INDEPENDENTLY ESTABLISHED FINDINGS",
        "8. RECOMMENDED VERIFICATION CHECKS",
        "9. EVIDENCE REFERENCES AND LIMITATIONS",
    ]
    positions = [text.find(m) for m in marks]
    assert all(p >= 0 for p in positions), positions
    return positions


def section(text, number):
    match = re.search(rf"^{number}\. .*?(?=^\d\. |\Z)", text, re.S | re.M)
    assert match, number
    return match.group(0)


# ================================================================ valid report


def test_valid_report_is_presented_in_the_required_order(payload):
    code, out, err = view(completed_server(payload))

    assert code == 0 and err == ""
    positions = section_positions(out)
    assert positions == sorted(positions)


def test_header_shows_question_namespace_id_and_status(payload):
    _, out, _ = view(completed_server(payload))
    header = section(out, 1)

    assert "namespace team-a." in header
    assert f"Namespace: {NS}" in header
    assert f"ID:        {ID}" in header
    assert "Status:    completed" in header
    assert "Duration:  3.1s" in header


def test_each_category_lands_in_its_section(payload):
    _, out, _ = view(completed_server(payload))

    assert "[warning]" in section(out, 2) and "unconditional exit" in section(out, 2)
    assert "restart count" in section(out, 3) and "readiness" in section(out, 3)
    assert "declares 1 environment variable" in " ".join(section(out, 4).split())
    assert "UNVERIFIED" in section(out, 5)
    assert "declares 1 environment variable" in " ".join(section(out, 6).split())
    assert "unconditional exit" in section(out, 7)
    assert "from unverified hypothesis 1" in section(out, 8)


def test_hypotheses_are_prominently_unverified_and_attributed(payload):
    _, out, _ = view(completed_server(payload))
    ai = section(out, 5)

    assert "UNVERIFIED: model-generated interpretations, NOT findings." in ai
    assert "Hypothesis 1 of 1 [UNVERIFIED]" in ai
    assert "Application reported (a claim, not verified):" in ai
    assert "Possible explanation:" in ai and "Not yet verified:" in ai
    # Not mixed into verified sections.
    for number in (2, 3, 4, 7):
        assert "Possible explanation" not in section(out, number)


def test_pod_discovery_and_implementation_detail_are_not_shown_by_default(payload):
    _, out, _ = view(completed_server(payload))

    assert "Pod discovered" not in out
    assert "successful Kubernetes pod listing" not in out
    assert "Observed during tool execution" not in out
    assert "Container logs retrieved" not in out


def test_verbose_shows_every_finding_with_its_evidence_references(payload, report):
    _, out, _ = view(completed_server(payload), "--verbose")
    verbose = out[out.index("ALL VERIFIED FINDINGS (verbose)"):]

    for finding in report.findings:
        assert finding.title in verbose
        for ref in finding.evidence:
            assert ref.evidence_id in verbose
    assert "Pod discovered" in verbose
    assert "AI analysis detail: state=generated" in verbose


def test_evidence_references_are_distinct_and_all_belong_to_the_report(payload, report):
    _, out, _ = view(completed_server(payload))
    cited = {r.evidence_id for f in report.findings for r in f.evidence}
    limitation = section(out, 9)

    assert f"{len(cited)} reference(s)" in limitation
    shown = set(re.findall(r"ev-[0-9]{4}", limitation))
    assert shown == cited


def test_hypothesis_citations_split_verified_evidence_from_transient_logs(payload):
    _, out, _ = view(completed_server(payload))
    cites = " ".join(section(out, 5).split())

    assert "verified evidence ev-" in cites
    assert "1 transient log excerpt(s) (log-0001; not retained, not shown)" in cites


def test_transient_log_use_is_disclosed_and_log_text_never_shown(payload):
    _, out, _ = view(completed_server(payload), "--verbose")
    text = " ".join(out.split())

    assert "1 bounded log excerpt(s) were read transiently in memory" in text
    assert "not stored in the report and are never displayed here" in text
    assert SENTINEL not in out
    for line in LOG_LINES:
        assert line not in out


def test_no_log_use_is_stated_plainly():
    quiet = make_report(ctx_kwargs=dict(logs=None), hypotheses=False)
    _, out, _ = view(completed_server(quiet.model_dump(mode="json")))

    assert "no log excerpts were used by AI analysis" in " ".join(out.split())


def test_omitted_log_excerpts_are_disclosed(payload):
    data = json.loads(json.dumps(payload))
    data["ai_analysis"]["log_excerpts_omitted"] = 3
    _, out, _ = view(completed_server(data))

    assert "3 further excerpt(s) were omitted by bounds" in " ".join(out.split())


def test_engine_finding_titles_are_all_known_to_the_viewer():
    """Drift guard: a new engine title must be classified, not silently hidden."""
    scenarios = [
        {}, dict(logs=None, config=False), dict(ready=True, restarts=0, observed_exit=0),
        dict(static_analysis="not_established"), dict(static_exit=2),
        dict(env=(), env_complete=False),
    ]
    for kwargs in scenarios:
        built = build_grounded_report(snap(build_context(**kwargs)))
        for finding in built.findings:
            assert finding.title in demo.BUCKET_BY_TITLE, finding.title


# ========================================================= degraded reports


def test_report_with_no_ai_sections_displays_deterministic_findings(payload):
    data = {k: v for k, v in payload.items() if k not in {"ai_hypotheses", "ai_analysis"}}
    code, out, _ = view(completed_server(data))

    assert code == 0
    assert "AI analysis is not part of this report." in out
    assert "None attached" in section(out, 6)
    assert "[warning]" in section(out, 2)


def test_minimal_report_with_missing_optional_fields_renders():
    data = {"investigation_id": ID, "summary": "Only a summary."}
    code, out, _ = view(completed_server(data))

    assert code == 0
    section_positions(out)
    assert "No warning-level findings were established." in out
    assert "No container symptoms were recorded" in out
    assert "None recommended." in out
    assert "(none recorded)" in out


def test_record_without_question_still_renders(payload):
    code, out, _ = view(completed_server(payload, user_text=None, stop_reason=None))

    assert code == 0 and "(question not recorded)" in out


@pytest.mark.parametrize(
    "state, expected",
    [
        ("none_proposed", "AI analysis ran and proposed no hypotheses."),
        ("not_attempted", "AI analysis was not attempted."),
    ],
)
def test_other_ai_states_are_explained(payload, state, expected):
    data = json.loads(json.dumps(payload))
    data["ai_hypotheses"] = []
    data["ai_analysis"].update(state=state, hypotheses_proposed=0)
    code, out, _ = view(completed_server(data))

    assert code == 0 and expected in out
    assert "Deterministic findings are complete and shown regardless." in out


def test_rejected_ai_batch_never_hides_deterministic_findings():
    contradiction = model_hypothesis(
        evidence=[], not_yet_verified="The workload configuration has not yet been inspected."
    )

    ctx = build_context(investigation_id=ID, env=(), env_complete=True)
    refs = full_refs(snap(ctx))
    contradiction["evidence"] = refs
    omitted = make_report(
        ctx_kwargs=dict(env=(), env_complete=True),
        provider=provider_returning(*[contradiction] * 4, investigation_id=ID),
    )
    code, out, _ = view(completed_server(omitted.model_dump(mode="json")))

    assert code == 0
    assert omitted.ai_hypotheses == []
    assert "No AI hypotheses accepted: all 4 proposed were omitted by validation." in out
    assert "contradicts_established_evidence x4" in out
    assert "[warning]" in section(out, 2)
    assert "restart count" in section(out, 3)
    assert "Deterministic findings are complete and shown regardless." in out


def test_unavailable_ai_stage_is_explained_with_its_category(payload):
    data = json.loads(json.dumps(payload))
    data["ai_hypotheses"] = []
    data["ai_analysis"].update(
        state="unavailable", reason="validation_failed", rejection_category="security"
    )
    _, out, _ = view(completed_server(data))

    assert "AI analysis was unavailable (validation_failed, security validation)" in out


def test_malformed_ai_section_does_not_hide_the_deterministic_report(payload):
    data = json.loads(json.dumps(payload))
    data["ai_hypotheses"] = [{"unexpected": "shape"}]
    code, out, _ = view(completed_server(data))

    assert code == 0
    assert "AI section could not be displayed" in out
    assert "[warning]" in section(out, 2)


# =================================================== invalid API responses


@pytest.mark.parametrize(
    "response",
    [
        lambda r: httpx.Response(200, content=b"<html>not json</html>"),
        lambda r: httpx.Response(200, json=["a", "list"]),
        lambda r: httpx.Response(200, json={"investigation_id": ID}),
    ],
)
def test_invalid_record_responses_are_rejected_with_fixed_messages(response):
    server = Server({("GET", f"/investigations/{ID}"): response})
    code, out, err = view(server)

    assert code == demo.EXIT_API and out == ""
    assert "Error:" in err and "<html>" not in err


def test_report_with_invalid_deterministic_part_is_an_error_not_a_crash(payload):
    data = dict(payload, findings="not-a-list")
    code, out, err = view(completed_server(data))

    assert code == demo.EXIT_API
    assert "report in an unexpected format" in err and out == ""


def test_report_for_another_investigation_is_refused(payload):
    data = dict(payload, investigation_id=str(uuid.uuid4()))
    code, out, err = view(completed_server(data))

    assert code == demo.EXIT_API and "different investigation" in err and out == ""


def test_response_bodies_and_exception_text_are_never_echoed():
    leak = "LEAKED-SERVER-INTERNALS-4417"
    cases = [
        Server({("GET", f"/investigations/{ID}"): (500, {"detail": leak})}),
        Server({("GET", f"/investigations/{ID}"): httpx.ConnectError(leak)}),
        Server({("GET", f"/investigations/{ID}"): httpx.ReadError(leak)}),
    ]
    for server in cases:
        code, out, err = view(server)
        assert code == demo.EXIT_API
        assert leak not in out + err


# ================================================================ auth etc.


def test_missing_api_key_still_calls_the_api():
    server = completed_server({})
    code, _, err = run(["--investigation-id", ID], server, env={})

    assert code == 0
    assert server.requests
    assert all("x-api-key" not in {name.lower() for name in request.headers} for request in server.requests)


def test_api_key_comes_from_the_environment_only():
    with pytest.raises(SystemExit):
        run(["--investigation-id", ID, "--api-key", "x"], completed_server({}))


def test_requests_do_not_send_an_api_key(payload):
    server = completed_server(payload)
    code, out, err = view(server, "--verbose")

    assert code == 0
    assert all("x-api-key" not in {name.lower() for name in request.headers} for request in server.requests)
    assert KEY not in out + err


def test_unauthorized_key_gives_a_clear_message_and_no_key_echo():
    server = Server({("GET", f"/investigations/{ID}"): (401, {"detail": "Invalid API key."})})
    code, out, err = view(server)

    assert code == demo.EXIT_API and out == ""
    assert "HTTP 401" in err
    assert KEY not in err


def test_forbidden_namespace_is_reported():
    server = Server({("POST", "/investigations"): (403, {"detail": "Namespace access denied."})})
    code, _, err = run(
        ["--namespace", "other-ns", "--question", "Investigate payments", "--live"], server
    )

    assert code == demo.EXIT_API and "HTTP 403" in err


def test_investigation_not_found():
    code, out, err = view(Server({}))

    assert code == demo.EXIT_API and out == ""
    assert "not found, or not accessible to this API key (HTTP 404)" in err


def test_api_unavailable_names_the_target_without_exception_text():
    code, _, err = view(Server({("GET", f"/investigations/{ID}"): httpx.ConnectError("boom")}))

    assert code == demo.EXIT_API
    assert "API is unavailable at http://127.0.0.1:8080" in err and "boom" not in err


def test_timeout_is_reported():
    code, _, err = view(Server({("GET", f"/investigations/{ID}"): httpx.ReadTimeout("slow")}))

    assert code == demo.EXIT_API and "timed out" in err and "slow" not in err


def test_plain_http_to_a_remote_host_is_refused_without_any_request():
    server = completed_server({})
    code, _, err = run(
        ["--investigation-id", ID, "--base-url", "http://api.example.com"], server
    )

    assert code == demo.EXIT_USAGE and "https" in err and server.requests == []


def test_https_remote_host_is_allowed(payload):
    server = completed_server(payload)
    code, _, _ = run(
        ["--investigation-id", ID, "--base-url", "https://api.example.com", "--color", "never"],
        server,
    )

    assert code == 0 and server.requests[0].url.host == "api.example.com"


def test_unexpected_internal_error_shows_only_the_exception_type(payload, monkeypatch):
    def boom(*a, **k):
        raise ValueError("internal-secret-detail")

    monkeypatch.setattr(demo, "render_report", boom)
    code, out, err = view(completed_server(payload))

    assert code == demo.EXIT_API
    assert "ValueError" in err and "internal-secret-detail" not in err + out


# ============================================================ status handling


@pytest.mark.parametrize(
    "status, phrase",
    [
        ("running", "still RUNNING"),
        ("pending", "PENDING"),
        ("failed", "FAILED. No report is available"),
    ],
)
def test_unfinished_or_failed_investigations_show_status_and_fetch_no_report(status, phrase):
    server = Server({("GET", f"/investigations/{ID}"): (200, record_payload(status))})
    code, out, err = view(server)

    assert code == demo.EXIT_NOT_COMPLETED and err == ""
    assert phrase in out and f"Status:    {status}" in out
    assert ("GET", f"/investigations/{ID}/report") not in server.paths


def test_wait_polls_until_the_investigation_completes(payload):
    states = iter(["running", "running", "completed"])
    sleeps = []

    def record(_request):
        return httpx.Response(200, json=record_payload(next(states)))

    server = Server(
        {
            ("GET", f"/investigations/{ID}"): record,
            ("GET", f"/investigations/{ID}/report"): (200, payload),
        }
    )
    code, out, _ = run(
        ["--investigation-id", ID, "--wait", "30", "--color", "never"],
        server,
        sleep=sleeps.append,
    )

    assert code == 0 and "[warning]" in out
    assert len(sleeps) == 2


def test_wait_gives_up_at_the_deadline():
    server = Server({("GET", f"/investigations/{ID}"): (200, record_payload("running"))})
    now = [0.0]
    out = io.StringIO()

    def sleep(seconds):
        now[0] += seconds

    code = demo.main(
        ["--investigation-id", ID, "--wait", "30", "--color", "never"],
        env={demo.API_KEY_ENV: KEY},
        out=out,
        err=io.StringIO(),
        transport=httpx.MockTransport(server),
        sleep=sleep,
        clock=lambda: now[0],
    )

    assert code == demo.EXIT_NOT_COMPLETED
    assert "still RUNNING" in out.getvalue() and "the wait elapsed" in out.getvalue()
    assert ("GET", f"/investigations/{ID}/report") not in server.paths
    # Bounded: 30s at 2s intervals, plus the initial read.
    assert len(server.requests) <= 17


def test_invalid_uuid_and_conflicting_modes_are_usage_errors():
    assert run(["--investigation-id", "not-a-uuid"], Server({}))[0] == demo.EXIT_USAGE
    assert run(["--investigation-id", ID, "--namespace", NS, "--question", "q"], Server({}))[0] == demo.EXIT_USAGE
    assert run([], Server({}))[0] == demo.EXIT_USAGE


# ===================================================== start-a-new-investigation


def new_server(payload, *, execute=(200, record_payload()), record_status="completed"):
    return Server(
        {
            ("POST", "/investigations"): (201, record_payload("pending", started_at=None, finished_at=None, stop_reason=None)),
            ("POST", f"/investigations/{ID}/execute"): execute,
            ("GET", f"/investigations/{ID}"): (200, record_payload(record_status)),
            ("GET", f"/investigations/{ID}/report"): (200, payload),
        }
    )


NEW_ARGS = ["--namespace", NS, "--question", "Investigate why billing is failing", "--live", "--color", "never"]


def test_new_investigation_runs_create_execute_fetch_in_order(payload):
    server = new_server(payload)
    code, out, err = run(NEW_ARGS, server)

    assert code == 0 and err == ""
    assert server.paths == [
        ("POST", "/investigations"),
        ("POST", f"/investigations/{ID}/execute"),
        ("GET", f"/investigations/{ID}"),
        ("GET", f"/investigations/{ID}/report"),
    ]
    assert f"Investigation {ID} created in namespace {NS}" in out
    assert "Timing: create" in out and "execute" in out and "report fetch" in out
    section_positions(out)


def test_namespace_is_sent_as_a_structured_field_and_the_question_is_not_rewritten(payload):
    server = new_server(payload)
    run(NEW_ARGS, server)

    body = json.loads(server.requests[0].content)
    assert body == {
        "question": "Investigate why billing is failing",
        "namespace": NS,
        "max_steps": 6,
    }
    # Scope never depends on text the viewer composed.
    assert "namespace" not in body["question"]


@pytest.mark.parametrize(
    "question",
    [
        "Investigate the health of the platform",  # broad, no verbs-nouns contract
        QUESTION,  # states the same namespace in text
        "Why is payments-api failing?",  # natural phrasing
    ],
)
def test_question_text_is_sent_exactly_as_the_user_wrote_it(payload, question):
    server = new_server(payload)
    run(["--namespace", NS, "--question", question, "--live", "--color", "never"], server)

    assert json.loads(server.requests[0].content)["question"] == question


@pytest.mark.parametrize(
    "question",
    ["Investigate billing in namespace other-ns", "Investigate namespace a and namespace b"],
)
def test_conflicting_namespace_is_left_to_the_server_to_reject_not_resolved_by_the_viewer(question):
    # The server owns this decision. The viewer must neither pick a namespace
    # nor rewrite the question; it sends both and reports the rejection.
    message = "The question refers to a namespace other than the one requested."
    server = Server({("POST", "/investigations"): (422, {"detail": message})})
    code, _, err = run(["--namespace", NS, "--question", question, "--live"], server)

    assert code == demo.EXIT_API and message in err and "HTTP 422" in err
    assert server.paths == [("POST", "/investigations")]
    body = json.loads(server.requests[0].content)
    assert body["question"] == question and body["namespace"] == NS


@pytest.mark.parametrize("message", sorted(demo.SCOPE_REJECTION_MESSAGES.values()))
def test_every_fixed_server_rejection_is_explained(message):
    server = Server({("POST", "/investigations"): (422, {"detail": message})})
    code, _, err = run(NEW_ARGS, server)

    assert code == demo.EXIT_API and message in err


def test_starting_requires_live_and_makes_no_request(payload):
    server = new_server(payload)
    code, _, err = run(["--namespace", NS, "--question", "Investigate billing"], server)

    assert code == demo.EXIT_USAGE and "--live" in err and server.requests == []


@pytest.mark.parametrize("extra", [["--max-steps", "0"], ["--max-steps", "11"]])
def test_step_budget_is_validated_locally(payload, extra):
    server = new_server(payload)
    code, _, _ = run([*NEW_ARGS, *extra], server)

    assert code == demo.EXIT_USAGE and server.requests == []


def test_unknown_or_hostile_422_detail_is_never_echoed():
    hostile = "\x1b]0;pwned\x07 Investigate with password=hunter2hunter2 \x1b[31mRED"
    server = Server({("POST", "/investigations"): (422, {"detail": hostile})})
    code, _, err = run(NEW_ARGS, server)

    assert code == demo.EXIT_API and "HTTP 422" in err
    assert "pwned" not in err and "hunter2" not in err and "\x1b" not in err
    assert "Check the namespace and the question." in err
    # The viewer reports the rejection; it does not retry with rewritten text.
    assert server.paths == [("POST", "/investigations")]


def test_non_string_422_detail_is_ignored():
    server = Server({("POST", "/investigations"): (422, {"detail": [{"msg": "x", "input": "secret"}]})})
    code, _, err = run(NEW_ARGS, server)

    assert code == demo.EXIT_API and "secret" not in err and "Check the namespace" in err


def test_execute_timeout_falls_back_to_the_real_status(payload):
    server = new_server(payload, execute=httpx.ReadTimeout("slow"), record_status="running")
    code, out, _ = run(NEW_ARGS, server)

    assert code == demo.EXIT_NOT_COMPLETED and "still RUNNING" in out


def test_execute_failure_shows_the_failed_investigation(payload):
    server = new_server(
        payload,
        execute=(500, {"detail": "Investigation execution failed."}),
        record_status="failed",
    )
    code, out, _ = run(NEW_ARGS, server)

    assert code == demo.EXIT_NOT_COMPLETED and "FAILED. No report is available" in out


def test_execute_error_with_no_progress_is_reported_as_an_error(payload):
    server = new_server(
        payload, execute=(500, {"detail": "x"}), record_status="pending"
    )
    code, out, err = run(NEW_ARGS, server)

    assert code == demo.EXIT_API and "HTTP 500" in err and out.count("created in namespace") == 1


def test_api_authorizing_a_different_namespace_is_refused(payload):
    server = new_server(payload)
    server.routes[("POST", "/investigations")] = (
        201, record_payload("pending", authorized_namespace="elsewhere")
    )
    code, _, err = run(NEW_ARGS, server)

    assert code == demo.EXIT_API and "different namespace" in err
    assert ("POST", f"/investigations/{ID}/execute") not in server.paths


def test_viewer_only_calls_the_existing_api_and_never_mutates_anything_else(payload):
    server = new_server(payload)
    run(NEW_ARGS, server)

    allowed = {
        ("POST", "/investigations"),
        ("POST", f"/investigations/{ID}/execute"),
        ("GET", f"/investigations/{ID}"),
        ("GET", f"/investigations/{ID}/report"),
    }
    assert set(server.paths) <= allowed


# ===================================================== terminal escape safety

HOSTILE = (
    "\x1b[2J\x1b[31mRED\x1b[0m \x1b]0;pwned-title\x07 \x1b]8;;http://evil\x1b\\link\x1b]8;;\x1b\\ "
    "\x9b31mC1\x9b \x1bPdcs\x1b\\ \u202eRTL\u202c zero\u200bwidth \x00nul \rovertype \x07bell \x08\x08back"
)


def hostile_payload(payload):
    data = json.loads(json.dumps(payload))
    data["summary"] = HOSTILE
    data["findings"][0]["title"] = HOSTILE
    data["findings"][0]["description"] = HOSTILE
    data["uncertainties"] = [HOSTILE]
    data["suggested_checks"] = [HOSTILE]
    h = data["ai_hypotheses"][0]
    for key in ("reported", "possible_explanation", "not_yet_verified",
                "verification_check", "configuration_context", "independently_established"):
        h[key] = HOSTILE
    data["ai_analysis"]["message"] = HOSTILE
    return data


def hostile_server(payload):
    return completed_server(
        hostile_payload(payload), user_text=HOSTILE, authorized_namespace=NS
    )


def test_safe_removes_escape_sequences_and_control_characters():
    cleaned = demo.safe(HOSTILE, 2000)

    assert not re.search(r"[\x00-\x1f\x7f-\x9f\u200b\u202a-\u202e]", cleaned)
    assert "pwned-title" not in cleaned and "evil" not in cleaned
    assert "[2J" not in cleaned and "dcs" not in cleaned
    for word in ("RED", "RTL", "nul", "overtype", "back"):
        assert word in cleaned  # visible text survives


@pytest.mark.parametrize("color", ["never", "always"])
def test_hostile_api_text_cannot_inject_terminal_sequences(payload, color):
    code, out, _ = run(
        ["--investigation-id", ID, "--color", color, "--verbose"],
        hostile_server(payload),
    )

    assert code == 0
    # Only this program's own fixed styling codes may appear, and only with --color always.
    stripped = re.sub(r"\x1b\[(?:1|1;33|2|0)m", "", out) if color == "always" else out
    assert "\x1b" not in stripped
    assert not re.search(r"[\x00-\x08\x0b-\x1a\x1c-\x1f\x7f-\x9f\u200b\u202a-\u202e\r]", stripped)
    assert "pwned-title" not in out and "http://evil" not in out


def test_hostile_text_does_not_hide_the_unverified_label(payload):
    _, out, _ = run(["--investigation-id", ID, "--color", "never"], hostile_server(payload))

    assert "Hypothesis 1 of 1 [UNVERIFIED]" in out
    assert "UNVERIFIED: model-generated interpretations, NOT findings." in out


def test_secret_like_text_from_the_api_is_redacted_again(payload):
    data = json.loads(json.dumps(payload))
    data["findings"][0]["description"] = (
        "Leaked sk-abcdef1234567890abcdef1234 and Bearer abcdefghijklmnop1234567890 here."
    )
    data["uncertainties"] = ["token=supersecretvalue1234567890abcdef was seen"]
    _, out, _ = view(completed_server(data), "--verbose")

    assert "sk-abcdef1234567890abcdef1234" not in out
    assert "abcdefghijklmnop1234567890" not in out
    assert "supersecretvalue1234567890abcdef" not in out
    assert "[REDACTED]" in out


def test_internal_execution_identifiers_are_not_shown_in_uncertainties(payload):
    data = json.loads(json.dumps(payload))
    data["uncertainties"] = [
        "Log retrieval for pod 'p' during execution 'abc-123-step-3' (k8s.get_logs) was bounded."
    ]
    _, out, _ = view(completed_server(data))

    assert "abc-123-step-3" not in out and "was bounded" in out


def test_color_is_off_by_default_when_not_a_terminal(payload):
    code, out, _ = run(["--investigation-id", ID], completed_server(payload))

    assert code == 0 and "\x1b" not in out


def test_styling_is_applied_only_to_fixed_labels(payload):
    _, out, _ = run(["--investigation-id", ID, "--color", "always"], completed_server(payload))

    assert "\x1b[1;33mUNVERIFIED\x1b[0m" in out


# ===================================================== deterministic content


def test_output_contains_no_environment_values_commands_or_variable_secrets(payload):
    _, out, _ = view(completed_server(payload), "--verbose")

    # The engine never collects these; the viewer must not invent or surface them.
    assert "command text is not collected" in " ".join(out.split())
    assert "echo " not in out and "/bin/sh" not in out
    # No NAME=value style assignments anywhere in the presentation.
    assert not re.search(r"\b[A-Z][A-Z0-9_]{3,}=\S", out)
    assert SENTINEL not in out


def test_viewer_uses_the_api_models_and_has_no_other_access_paths():
    source = open(demo.__file__).read()

    for forbidden in ("psycopg", "kubernetes", "subprocess", "InvestigationRepository",
                      "build_investigation_service", "build_grounded_report", "KUBECONFIG"):
        assert forbidden not in source, forbidden


# ============================================================ presentation polish


def normalized(text):
    return " ".join(text.split())


def top_finding(payload):
    [finding] = [f for f in payload["findings"] if f["severity"] == "warning"]
    return finding


def test_top_finding_is_shown_once_prominently_with_its_full_description(payload):
    _, out, _ = view(completed_server(payload))
    finding = top_finding(payload)
    first_sentence = normalized(finding["description"]).split(". ")[0][:80]

    assert normalized(out).count(first_sentence) == 1
    assert first_sentence in normalized(section(out, 2))
    assert ">> [warning]" in section(out, 2)
    # Never a second "Warning-level and above" listing of the same finding.
    assert "Warning-level and above" not in out


def test_engine_summary_list_is_not_repeated_but_headline_and_caveat_are_kept(payload):
    _, out, _ = view(completed_server(payload))
    two = section(out, 2)

    assert "Most significant findings" not in two
    assert not re.search(r"^\s+\d+\. \[", two, re.M)
    assert "verified finding(s)" in two
    assert "remain unverified" in normalized(two)


def test_independent_evidence_sits_beside_the_hypothesis_without_its_description(payload):
    _, out, _ = view(completed_server(payload))
    ai = normalized(section(out, 5))
    description = normalized(top_finding(payload)["description"])

    assert "Independent evidence:" in ai and "(section 7)" in ai
    assert description[:60] not in ai


def test_section_seven_points_back_instead_of_repeating(payload):
    _, out, _ = view(completed_server(payload))
    seven = normalized(section(out, 7))
    title = top_finding(payload)["title"]

    assert title in seven and "described in section 2" in seven
    assert "Accompanies hypothesis 1." in seven
    # The application annotation for the same evidence is folded in, not repeated.
    assert "alongside hypothesis" not in seven
    assert normalized(top_finding(payload)["description"])[:60] not in seven


def test_an_annotation_on_different_evidence_is_still_shown_in_full(payload):
    forged = json.loads(json.dumps(payload))
    forged["ai_hypotheses"][0]["established_refs"] = ["ev-0001"]
    _, out, _ = view(completed_server(forged))
    seven = normalized(section(out, 7))

    assert "alongside hypothesis 1" in seven
    assert forged["ai_hypotheses"][0]["independently_established"][:60] in seven
    assert "application-written corroboration (section 7)" in normalized(section(out, 5))


def test_verbose_preserves_every_finding_citation_and_detail(payload):
    _, default, _ = view(completed_server(payload))
    _, verbose, _ = view(completed_server(payload), "--verbose")
    flat = normalized(verbose)

    for number, finding in enumerate(payload["findings"], start=1):
        assert normalized(finding["title"]) in flat
        assert normalized(finding["description"])[:80] in flat
        for ref in finding["evidence"]:
            assert ref["evidence_id"] in verbose
    # Verbose is a superset of the default view's references and sections.
    for ref in re.findall(r"ev-\d{4}", default):
        assert ref in verbose
    assert "Stop:      provider_finished" in verbose


def test_internal_stop_reason_is_not_shown_by_default(payload):
    _, out, _ = view(completed_server(payload))

    assert "provider_finished" not in out and "Stop:" not in out


def test_stop_reason_is_still_shown_when_there_is_no_report():
    server = Server({("GET", f"/investigations/{ID}"): (200, record_payload("failed", stop_reason="tool_error"))})
    _, out, _ = view(server)

    assert "Stop:      tool_error" in out


def test_summary_without_the_expected_shape_is_shown_whole():
    headline, tail = demo._split_summary("One line only.\nAnother line.")

    assert headline == ["One line only.", "Another line."] and tail == []
    assert demo._split_summary("") == ([], [])


def test_no_hypothesis_still_shows_the_top_finding_once():
    report = make_report(hypotheses=False)
    payload = report.model_dump(mode="json")
    _, out, _ = view(completed_server(payload))
    finding = top_finding(payload)
    first_sentence = normalized(finding["description"]).split(". ")[0][:80]

    assert normalized(out).count(first_sentence) == 1
    assert "described in section 2" in normalized(section(out, 7))
    assert "Independent evidence:" not in out


def test_default_view_points_to_verbose_for_the_full_finding_list(payload):
    _, default, _ = view(completed_server(payload))
    _, verbose, _ = view(completed_server(payload), "--verbose")
    count = len(payload["findings"])

    assert f"Use --verbose to list all {count} findings" in normalized(default)
    assert "Use --verbose to list all" not in verbose
