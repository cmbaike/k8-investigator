"""Cross-evidence correlation, AI-analysis states and evidence-aware checks.

Deliberately uses workload, pod and variable names that appear nowhere in the
demo, to show the behaviour is not tied to a specific failure. No model,
cluster, network or database is contacted.
"""

import json
from types import SimpleNamespace

import pytest

from app.reports.checks import build_coverage_uncertainties, build_suggested_checks
from app.reports.enrichment import add_ai_hypotheses
from app.reports.grounding import build_grounded_report
from app.reports.hypotheses import (
    HypothesisBatch,
    HypothesisEvidenceRegistry,
    categorize_rejection,
    parse_hypothesis_response,
    revalidate_hypotheses,
)
from app.reports.models import AIHypothesis
from app.reports.qwen_hypotheses import (
    HYPOTHESIS_SYSTEM_PROMPT,
    QwenHypothesisProvider,
)
from app.reports.snapshot import build_investigation_evidence_snapshot
from app.tools.investigation import InvestigationContext
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus
from app.tools.workload_config import WORKLOAD_CONFIG_TOOL

NS = "team-a"
POD = "billing-svc-6d8f7-xk2pq"
DEPLOY = "billing-svc"
SENTINEL = "QZ7-RAW-LOG-SENTINEL-902"
ENV = "SERVICE_ENDPOINT"
LOG_LINES = [
    f"fatal: required setting {ENV} is not set",
    f"{SENTINEL} startup aborted",
]

REPORTED = f"the required setting {ENV} is not set"
POSSIBLE = (
    "The container may be exiting because a required setting is reported "
    "missing, although its declared startup may also exit regardless of the "
    "environment."
)
NOT_VERIFIED = (
    "Whether the setting is actually missing has not been verified, and the "
    "startup exit has not been tested against changed configuration."
)
CHECK = (
    "Review the Deployment definition and declared environment variable "
    "names through read-only describe output."
)


def ok(call, output):
    return ToolExecutionResult(
        tool=call.name, status=ToolExecutionStatus.SUCCESS, output=output
    )


def build_context(
    *,
    logs=LOG_LINES,
    config=True,
    observed_exit=1,
    static_exit=1,
    static_analysis="unconditional_exit",
    ready=False,
    restarts=4,
    investigation_id="inv-corr",
    env=(("LOG_LEVEL", "literal"),),
    env_complete=True,
):
    ctx = InvestigationContext(
        investigation_id=investigation_id,
        user_text=f"Investigate the failing workload in namespace {NS}.",
        authorized_namespace=NS,
        max_steps=10,
    )

    def run(request_id, name, arguments, output):
        call = ToolCall(name=name, arguments=arguments)
        ctx.record_execution(
            request_id=request_id, call=call, result=ok(call, output)
        )

    run("r1", "k8s.get_pods", {"namespace": NS},
        {"namespace": NS, "pods": [{"name": POD}]})

    container = {
        "name": "main",
        "ready": ready,
        "restart_count": restarts,
        "state": "waiting" if not ready else "running",
        "last_termination": {"exit_code": observed_exit, "reason": "Error"},
    }
    if not ready:
        container["reason"] = "CrashLoopBackOff"

    run("r2", "k8s.describe_pod", {"namespace": NS, "pod": POD},
        {"namespace": NS, "name": POD, "phase": "Running",
         "containers": [container]})

    if config:
        startup = {
            "command_declared": True,
            "args_declared": True,
            "entrypoint_kind": "shell_script",
            "static_analysis": static_analysis,
            "static_exit_code": (
                static_exit if static_analysis == "unconditional_exit" else None
            ),
        }
        run("r3", WORKLOAD_CONFIG_TOOL, {"namespace": NS, "pod": POD},
            {
                "namespace": NS, "pod": POD,
                "workload": {
                    "kind": "Deployment", "name": DEPLOY,
                    "replicaset": f"{DEPLOY}-6d8f7", "ownership_verified": True,
                    "desired_replicas": 1, "ready_replicas": 0,
                    "available_replicas": 0, "updated_replicas": 1,
                },
                "containers": [{
                    "name": "main",
                    "image": "registry.example.com/team/billing:2.0.1",
                    "env_count": len(env),
                    "env": [{"name": n, "source": src} for n, src in env],
                    "env_truncated": False,
                    "env_names_complete": env_complete,
                    "startup": startup,
                }],
            })

    if logs is not None:
        run("r4", "k8s.get_logs",
            {"namespace": NS, "pod": POD, "container": "main"},
            {"namespace": NS, "pod": POD, "container": "main", "tail": 200,
             "previous": False, "logs": "\n".join(logs),
             "completeness": "bounded_unknown"})

    return ctx


def snap(ctx):
    return build_investigation_evidence_snapshot(ctx)


def evid(snapshot, field, tool=None):
    return next(
        i.evidence_id for i in snapshot.evidence
        if i.field == field and (tool is None or i.tool == tool)
    )


def registry_for(ctx, snapshot):
    return HypothesisEvidenceRegistry(
        investigation_id=ctx.investigation_id,
        authorized_namespace=NS,
        snapshot=snapshot,
        log_entries=ctx.log_entries,
    )


def model_hypothesis(**over):
    value = {
        "reported": REPORTED,
        "possible_explanation": POSSIBLE,
        "not_yet_verified": NOT_VERIFIED,
        "evidence": [],
        "resource": {"namespace": NS, "pod": POD, "container": "main"},
        "verification_check": CHECK,
    }
    value.update(over)
    return value


def provider_returning(*items, investigation_id="inv-corr", raw=None):
    content = raw if raw is not None else json.dumps(
        {"investigation_id": investigation_id, "hypotheses": list(items)}
    )

    def completion(**_kwargs):
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )

    return QwenHypothesisProvider(completion=completion)


def enrich(ctx, provider):
    snapshot = snap(ctx)
    base = build_grounded_report(snapshot)
    return base, add_ai_hypotheses(
        base, snapshot=snapshot, context=ctx, provider=provider
    )


def full_refs(snapshot, *, logs=True):
    refs = [
        evid(snapshot, "containers[main].last_termination.exit_code"),
        evid(snapshot, "containers[main].startup.static_analysis"),
        evid(snapshot, "containers[main].env.names_complete"),
    ]
    return refs + (["log-0001"] if logs else [])


# =========================================================== AI states


def test_state_all_omitted_when_every_proposal_claims_logs_that_do_not_exist():
    ctx = build_context(logs=None)
    snapshot = snap(ctx)
    refs = full_refs(snapshot, logs=False)
    # Four proposals, each describing "what the logs report" with no logs.
    proposals = [model_hypothesis(evidence=refs) for _ in range(4)]

    base, report = enrich(ctx, provider_returning(*proposals))
    analysis = report.ai_analysis

    assert report.ai_hypotheses == []
    assert analysis.state == "all_omitted"
    assert (analysis.hypotheses_proposed, analysis.hypotheses_omitted) == (4, 4)
    assert analysis.omission_reasons == {"reported_without_log_evidence": 4}
    assert analysis.log_excerpts_used == 0
    assert "no log excerpts" in analysis.message
    # Deterministic content is untouched.
    assert report.findings == base.findings
    assert report.uncertainties == base.uncertainties
    assert report.suggested_checks == base.suggested_checks


def test_state_generated_reports_accepted_and_omitted_counts():
    ctx = build_context()
    snapshot = snap(ctx)
    refs = full_refs(snapshot)
    good = model_hypothesis(evidence=refs)
    bad = model_hypothesis(
        evidence=refs,
        possible_explanation="The missing setting is the root cause.",
    )

    _, report = enrich(ctx, provider_returning(good, bad))
    analysis = report.ai_analysis

    assert analysis.state == "generated"
    assert len(report.ai_hypotheses) == 1
    assert (analysis.hypotheses_proposed, analysis.hypotheses_omitted) == (2, 1)
    assert sum(analysis.omission_reasons.values()) == 1
    assert analysis.log_excerpts_used == 1


def test_state_none_proposed_when_model_returns_an_empty_list():
    _, report = enrich(build_context(), provider_returning())

    assert report.ai_analysis.state == "none_proposed"
    assert report.ai_analysis.hypotheses_proposed == 0
    assert report.ai_hypotheses == []


def test_state_not_attempted_without_evidence():
    ctx = InvestigationContext(
        investigation_id="inv-empty", user_text="x", authorized_namespace=NS
    )
    snapshot = build_investigation_evidence_snapshot(ctx)
    base = build_grounded_report(snapshot)

    report = add_ai_hypotheses(
        base, snapshot=snapshot, context=ctx, provider=provider_returning()
    )

    assert report.ai_analysis.state == "not_attempted"
    assert report.ai_analysis.reason == "no_evidence"


def test_no_provider_leaves_the_report_without_an_ai_section():
    ctx = build_context()
    snapshot = snap(ctx)
    base = build_grounded_report(snapshot)

    assert (
        add_ai_hypotheses(base, snapshot=snapshot, context=ctx, provider=None)
        is base
    )
    assert base.ai_analysis is None


# ===================================== rejection categories (no weakening)


@pytest.mark.parametrize(
    "mutate, category",
    [
        # provenance: citation that does not exist in this investigation
        (lambda h, refs: h.update(evidence=refs + ["ev-0099"]), "provenance"),
        (lambda h, refs: h.update(evidence=["log-0042"]), "provenance"),
        # security: reproduces a credential-looking string
        (
            lambda h, refs: h.update(
                not_yet_verified="Token sk-abcdef1234567890abcdef was seen "
                "and has not been verified."
            ),
            "security",
        ),
        # security: a mutating check
        (
            lambda h, refs: h.update(verification_check="kubectl delete pod x"),
            "security",
        ),
    ],
)
def test_whole_response_rejections_are_categorized_without_text(mutate, category):
    ctx = build_context()
    refs = full_refs(snap(ctx))
    item = model_hypothesis(evidence=refs)
    mutate(item, refs)

    _, report = enrich(ctx, provider_returning(item))
    analysis = report.ai_analysis

    assert analysis.state == "unavailable"
    assert analysis.reason == "validation_failed"
    assert analysis.rejection_category == category
    assert report.ai_hypotheses == []
    dumped = report.model_dump_json()
    assert "kubectl" not in dumped and "sk-abcdef" not in dumped


def test_structure_failures_are_categorized():
    ctx = build_context()
    item = model_hypothesis(evidence=full_refs(snap(ctx)), severity="critical")

    _, report = enrich(ctx, provider_returning(item))

    assert report.ai_analysis.state == "unavailable"
    assert report.ai_analysis.rejection_category == "structure"


def test_unparseable_response_is_malformed_not_a_validation_category():
    _, report = enrich(build_context(), provider_returning(raw="not json"))

    assert report.ai_analysis.reason == "malformed_response"
    assert report.ai_analysis.rejection_category is None


def test_wording_failures_never_reject_the_whole_response_or_weaken_security():
    ctx = build_context()
    refs = full_refs(snap(ctx))
    wording = model_hypothesis(
        evidence=refs, possible_explanation="This is certainly the cause."
    )
    unsafe = model_hypothesis(
        evidence=refs, verification_check="Run rm -rf / on the node."
    )

    _, only_wording = enrich(ctx, provider_returning(wording))
    _, with_unsafe = enrich(ctx, provider_returning(wording, unsafe))

    assert only_wording.ai_analysis.state == "all_omitted"
    # The unsafe check still rejects everything: tone omission cannot mask it.
    assert with_unsafe.ai_analysis.state == "unavailable"
    assert with_unsafe.ai_analysis.rejection_category == "security"


@pytest.mark.parametrize(
    "code, category",
    [
        ("unknown_reference", "provenance"),
        ("resource_mismatch", "provenance"),
        ("cross_investigation", "provenance"),
        ("secret_reproduction", "security"),
        ("unsafe_check", "security"),
        ("schema", "structure"),
        ("unexpected_fields", "structure"),
    ],
)
def test_categorize_rejection(code, category):
    assert categorize_rejection(code) == category


def test_omission_reason_vocabulary_is_closed():
    from app.reports.models import AIAnalysisStatus

    with pytest.raises(ValueError):
        AIAnalysisStatus(
            state="all_omitted", message="x", omission_reasons={"free text": 1}
        )


def test_log_attribution_codes_are_distinguished():
    ctx = build_context()
    refs = full_refs(snap(ctx))
    cites_log_without_reporting = model_hypothesis(evidence=refs, reported=None)

    _, report = enrich(ctx, provider_returning(cites_log_without_reporting))

    assert report.ai_analysis.omission_reasons == {"unattributed_log_claim": 1}


# =============================================== cross-evidence reasoning


def test_hypothesis_cites_logs_config_and_termination_and_is_unverified():
    ctx = build_context()
    snapshot = snap(ctx)
    refs = full_refs(snapshot)

    _, report = enrich(ctx, provider_returning(model_hypothesis(evidence=refs)))
    [h] = report.ai_hypotheses

    assert h.status == "unverified"
    assert set(refs) <= set(h.evidence_refs)
    # The application claim stays an attributed paraphrase, not a fact.
    assert h.explanation.startswith("The application logs report that ")
    assert "Possible explanation (unverified):" in h.explanation
    assert "Not yet verified:" in h.explanation


def test_established_exit_is_attached_by_the_application_not_the_model():
    ctx = build_context()
    snapshot = snap(ctx)
    refs = full_refs(snapshot)
    # The model blames the setting and never mentions the unconditional exit.
    _, report = enrich(ctx, provider_returning(model_hypothesis(evidence=refs)))
    [h] = report.ai_hypotheses

    assert "unconditional exit" in h.independently_established
    assert "environment variable values alone" in h.independently_established
    assert "exit code 1" in h.independently_established
    known = {i.evidence_id for i in snapshot.evidence}
    assert h.established_refs and set(h.established_refs) <= known
    # It is not part of the model-influenced explanation text.
    assert "unconditional" not in h.explanation
    assert h.independently_established not in h.explanation


def test_established_text_is_identical_whatever_the_model_says():
    ctx = build_context()
    refs = full_refs(snap(ctx))
    first = model_hypothesis(evidence=refs)
    second = model_hypothesis(
        evidence=refs,
        reported="startup aborted",
        possible_explanation="The process may be failing early, which could "
        "explain the restarts.",
    )

    _, report = enrich(ctx, provider_returning(first, second))

    assert len(report.ai_hypotheses) == 2
    assert (
        report.ai_hypotheses[0].independently_established
        == report.ai_hypotheses[1].independently_established
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(static_analysis="not_established"),
        dict(static_exit=2),  # static code differs from the observed exit
        dict(config=False),
    ],
)
def test_nothing_is_claimed_as_established_without_corroboration(kwargs):
    ctx = build_context(**kwargs)
    snapshot = snap(ctx)
    refs = [
        evid(snapshot, "containers[main].last_termination.exit_code"),
        "log-0001",
    ]

    _, report = enrich(ctx, provider_returning(model_hypothesis(evidence=refs)))
    [h] = report.ai_hypotheses

    assert h.independently_established is None
    assert h.established_refs == []


def test_reported_missing_setting_never_becomes_a_verified_finding():
    ctx = build_context()
    base, report = enrich(
        ctx, provider_returning(model_hypothesis(evidence=full_refs(snap(ctx))))
    )

    deterministic = [f.title + " " + f.description for f in report.findings]
    assert report.findings == base.findings
    assert not any(ENV in text for text in deterministic)
    assert not any("root cause" in text.lower() for text in deterministic)


def test_model_claiming_the_setting_is_the_verified_root_cause_is_omitted():
    ctx = build_context()
    refs = full_refs(snap(ctx))
    claim = model_hypothesis(
        evidence=refs,
        possible_explanation="The root cause is the missing setting.",
        not_yet_verified="The cause has been confirmed.",
    )

    _, report = enrich(ctx, provider_returning(claim))

    assert report.ai_hypotheses == []
    assert report.ai_analysis.state == "all_omitted"
    assert "verified_claim" in report.ai_analysis.omission_reasons


def test_provider_supplied_established_text_must_match_application_value():
    ctx = build_context()
    snapshot = snap(ctx)
    registry = registry_for(ctx, snapshot)
    refs = full_refs(snapshot)
    [good] = parse_hypothesis_response(
        json.dumps({
            "investigation_id": "inv-corr",
            "hypotheses": [model_hypothesis(evidence=refs)],
        }),
        registry=registry,
        expected_investigation_id="inv-corr",
    ).hypotheses

    forged = good.model_copy(
        update={"independently_established": "Verified: the setting is fine."}
    )

    from app.reports.hypotheses import HypothesisValidationError

    with pytest.raises(HypothesisValidationError):
        revalidate_hypotheses([forged], registry=registry)

    assert revalidate_hypotheses([good], registry=registry).hypotheses == [good]


def test_prompt_requires_null_reported_when_no_logs_and_cross_checking():
    assert "MUST be null" in HYPOTHESIS_SYSTEM_PROMPT
    assert "verified_configuration_evidence" in HYPOTHESIS_SYSTEM_PROMPT
    assert "does not depend on the environment" in HYPOTHESIS_SYSTEM_PROMPT


# ================================================ persistence / secrets


def test_enriched_report_contains_no_raw_log_text_or_secrets():
    ctx = build_context()
    refs = full_refs(snap(ctx))

    _, report = enrich(ctx, provider_returning(model_hypothesis(evidence=refs)))
    dumped = report.model_dump_json()

    assert SENTINEL not in dumped
    for line in LOG_LINES:
        assert line not in dumped
    # Reports round-trip through the strict model unchanged.
    assert type(report).model_validate_json(dumped) == report


# =================================================== checks / uncertainty


def test_failing_container_without_logs_or_config_is_disclosed_and_actioned():
    ctx = build_context(logs=None, config=False)
    snapshot = snap(ctx)

    uncertainties = build_coverage_uncertainties(snapshot)
    checks = build_suggested_checks(snapshot)

    assert any("no container logs were retrieved" in u for u in uncertainties)
    assert any("workload configuration was not inspected" in u
               for u in uncertainties)
    assert any("Retrieve the bounded application logs" in c for c in checks)
    assert any("Inspect the owning Deployment's configuration" in c
               for c in checks)
    assert not any(c.startswith("Inspect pod status") for c in checks)


def test_checks_do_not_repeat_completed_steps_and_state_the_established_exit():
    ctx = build_context()
    snapshot = snap(ctx)

    checks = build_suggested_checks(snapshot)

    assert build_coverage_uncertainties(snapshot) == []
    assert not any("Retrieve the bounded application logs" in c for c in checks)
    assert not any("Inspect the owning Deployment" in c for c in checks)
    assert not any(c.startswith("Inspect pod status") for c in checks)
    assert not any("Review structured container restart" in c for c in checks)
    assert any(
        "exits unconditionally with code 1" in c
        and "Changing environment variables alone" in c
        for c in checks
    )
    assert any("Compare what the application logs report" in c for c in checks)


def test_mismatched_exit_codes_ask_for_reinspection_not_a_conclusion():
    snapshot = snap(build_context(static_exit=2))

    checks = build_suggested_checks(snapshot)

    assert any("differs from the exit code Kubernetes last reported" in c
               for c in checks)
    assert not any("exits unconditionally" in c for c in checks)


def test_unestablished_startup_is_called_out():
    snapshot = snap(build_context(static_analysis="not_established"))

    assert any(
        "could not be established by static analysis" in c
        for c in build_suggested_checks(snapshot)
    )


def test_healthy_workload_gets_no_failure_followups():
    ctx = build_context(ready=True, restarts=0, logs=None, config=False,
                        observed_exit=0)
    snapshot = snap(ctx)

    assert build_coverage_uncertainties(snapshot) == []
    [check] = build_suggested_checks(snapshot)
    assert "No failing container was established" in check


def test_without_pod_state_the_baseline_checks_remain():
    ctx = InvestigationContext(
        investigation_id="inv-x", user_text="x", authorized_namespace=NS
    )
    call = ToolCall(name="k8s.get_pods", arguments={"namespace": NS})
    ctx.record_execution(
        request_id="r1", call=call,
        result=ok(call, {"namespace": NS, "pods": [{"name": POD}]}),
    )

    assert build_suggested_checks(build_investigation_evidence_snapshot(ctx)) == [
        "Inspect pod status and readiness using authorized read-only tools.",
        "Review structured container restart information.",
    ]


def test_suggested_checks_are_read_only_bounded_and_secret_free():
    from app.reports.hypotheses import _UNSAFE_CHECK

    for kwargs in (
        {}, dict(logs=None), dict(config=False), dict(static_exit=2),
        dict(static_analysis="not_established"),
    ):
        ctx = build_context(**kwargs)
        report = build_grounded_report(snap(ctx))

        assert len(report.suggested_checks) <= 20
        for check in report.suggested_checks:
            assert not _UNSAFE_CHECK.search(check), check
            assert SENTINEL not in check and ENV not in check
            assert "kubectl" not in check.lower()


def test_grounded_report_carries_coverage_gaps_and_new_checks():
    report = build_grounded_report(snap(build_context(logs=None)))

    assert any("no container logs were retrieved" in u
               for u in report.uncertainties)
    assert any("Retrieve the bounded application logs" in c
               for c in report.suggested_checks)
    # The established exit finding is preserved, not weakened.
    assert any(
        "unconditional" in f.title.lower() or "unconditional" in f.description
        for f in report.findings
    )
