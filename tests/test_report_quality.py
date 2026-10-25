"""Report quality: consistency with established configuration evidence, and
the deterministic evidence-prioritized summary.

Uses names that appear nowhere in the demo. No model, cluster or database.
"""

import json

import pytest

from app.reports.config_grounding import (
    CONFIGURATION_SCOPE_NOTE,
    configuration_context_for,
)
from app.reports.enrichment import add_ai_hypotheses
from app.reports.grounding import build_grounded_report
from app.reports.hypotheses import (
    HypothesisValidationError,
    parse_hypothesis_response,
    revalidate_hypotheses,
)
from app.reports.models import InvestigationFinding, EvidenceReference
from app.reports.qwen_hypotheses import build_hypothesis_messages
from app.reports.hypotheses import HypothesisInput
from app.reports.summary import build_summary, rank_findings
from app.tools.investigation import InvestigationContext

from tests.test_diagnostic_correlation import (
    CHECK,
    NOT_VERIFIED,
    NS,
    POD,
    POSSIBLE,
    REPORTED,
    SENTINEL,
    build_context,
    enrich,
    evid,
    full_refs,
    model_hypothesis,
    provider_returning,
    registry_for,
    snap,
)

NONE_DECLARED = dict(env=(), env_complete=True)
ENV_FROM = dict(env=(), env_complete=False)


def refs_available(snapshot):
    """Citations that exist for this context (config evidence may be absent)."""
    wanted = [
        "containers[main].last_termination.exit_code",
        "containers[main].startup.static_analysis",
        "containers[main].env.names_complete",
        "logs.retrieved",
    ]
    present = {i.field: i.evidence_id for i in snapshot.evidence}
    refs = [present[f] for f in wanted[:3] if f in present]
    return refs + ["log-0001"]


def accepted(ctx, **over):
    refs = refs_available(snap(ctx))
    _, report = enrich(
        ctx, provider_returning(model_hypothesis(evidence=refs, **over))
    )
    return report


# ========================================== configuration annotation


def test_none_declared_is_stated_with_a_runtime_environment_caveat():
    ctx = build_context(**NONE_DECLARED)
    context = configuration_context_for(snap(ctx), NS, POD, "main")

    assert "declares no environment variables and no ConfigMap or Secret" in context.text
    assert CONFIGURATION_SCOPE_NOTE in context.text
    assert "does not show the complete runtime environment" in context.text
    assert context.none_declared and not context.declared_any
    assert context.startup_established


def test_envfrom_sources_are_not_treated_as_nothing_declared():
    ctx = build_context(**ENV_FROM)
    context = configuration_context_for(snap(ctx), NS, POD, "main")

    assert "no individual environment variables" in context.text
    assert not context.none_declared
    # Not claiming the spec declares nothing at all.
    assert "no ConfigMap or Secret" not in context.text


def test_declared_names_and_sources_are_listed_from_evidence_only():
    ctx = build_context(env=(("ALPHA_SETTING", "literal"), ("BETA_SETTING", "secret_reference")))
    context = configuration_context_for(snap(ctx), NS, POD, "main")

    assert "declares 2 environment variable(s)" in context.text
    assert "ALPHA_SETTING (literal value)" in context.text
    assert "BETA_SETTING (Secret reference)" in context.text
    known = {i.evidence_id for i in snap(ctx).evidence}
    assert context.refs and set(context.refs) <= known and len(context.refs) <= 6


def test_long_name_lists_are_bounded():
    env = tuple((f"VAR_{i}", "literal") for i in range(12))
    context = configuration_context_for(snap(build_context(env=env)), NS, POD, "main")

    assert "and 8 more" in context.text
    assert len(context.refs) <= 6
    assert len(context.text) <= 1000


def test_no_annotation_when_configuration_was_not_inspected():
    ctx = build_context(config=False)

    assert configuration_context_for(snap(ctx), NS, POD, "main") is None
    [h] = accepted(ctx).ai_hypotheses
    assert h.configuration_context is None and h.configuration_refs == []


def test_annotation_is_attached_by_the_application_next_to_the_hypothesis():
    report = accepted(build_context(**NONE_DECLARED))
    [h] = report.ai_hypotheses

    assert "declares no environment variables" in h.configuration_context
    assert CONFIGURATION_SCOPE_NOTE in h.configuration_context
    assert h.configuration_refs
    # Four kinds of information stay in separate fields.
    assert h.reported and "unconditional" in h.independently_established
    assert h.configuration_context not in h.explanation
    assert "declares no" not in h.explanation


def test_annotation_does_not_depend_on_what_the_model_says():
    ctx = build_context(**NONE_DECLARED)
    refs = full_refs(snap(ctx))
    other = model_hypothesis(
        evidence=refs,
        reported="startup aborted",
        possible_explanation="The process may be failing early, which could "
        "explain the restarts.",
    )
    _, report = enrich(
        ctx, provider_returning(model_hypothesis(evidence=refs), other)
    )

    first, second = report.ai_hypotheses
    assert first.configuration_context == second.configuration_context


def test_forged_configuration_context_is_rejected_on_revalidation():
    ctx = build_context(**NONE_DECLARED)
    snapshot = snap(ctx)
    registry = registry_for(ctx, snapshot)
    [good] = parse_hypothesis_response(
        json.dumps({
            "investigation_id": "inv-corr",
            "hypotheses": [model_hypothesis(evidence=full_refs(snapshot))],
        }),
        registry=registry,
        expected_investigation_id="inv-corr",
    ).hypotheses

    forged = good.model_copy(
        update={"configuration_context": "Container 'main' declares 9 variables."}
    )

    with pytest.raises(HypothesisValidationError):
        revalidate_hypotheses([forged], registry=registry)

    assert revalidate_hypotheses([good], registry=registry).hypotheses == [good]


# ============================== contradictory model uncertainty statements


@pytest.mark.parametrize(
    "claim",
    [
        "The workload configuration has not yet been inspected.",
        "Environment variable declarations have not been examined.",
        "The workload configuration and startup behavior have not yet been verified.",
        "It is unknown what the container configuration declares.",
    ],
)
def test_claiming_inspected_configuration_was_not_inspected_is_omitted(claim):
    ctx = build_context(**NONE_DECLARED)

    report = accepted(ctx, not_yet_verified=claim)

    assert report.ai_hypotheses == []
    assert report.ai_analysis.state == "all_omitted"
    assert report.ai_analysis.omission_reasons == {
        "contradicts_established_evidence": 1
    }


def test_same_wording_is_fine_when_configuration_really_was_not_inspected():
    ctx = build_context(config=False)

    report = accepted(
        ctx,
        not_yet_verified="The workload configuration and startup behavior "
        "have not yet been verified.",
    )

    assert len(report.ai_hypotheses) == 1


def test_startup_claims_only_contradict_when_startup_was_established():
    claim = "The startup behavior of the container has not yet been verified."

    established = accepted(build_context(), not_yet_verified=claim)
    not_established = accepted(
        build_context(static_analysis="not_established"), not_yet_verified=claim
    )

    assert established.ai_hypotheses == []
    assert established.ai_analysis.omission_reasons == {
        "contradicts_established_evidence": 1
    }
    assert len(not_established.ai_hypotheses) == 1


@pytest.mark.parametrize(
    "legitimate",
    [
        "The values of the declared variables have not been verified.",
        "Variables supplied by other mechanisms have not been established.",
        "Whether the setting is actually supplied at runtime has not been verified.",
        "The contents of any ConfigMap or Secret have not been inspected.",
        "Whether the logged claim is accurate has not been verified.",
    ],
)
def test_legitimate_uncertainty_about_what_is_not_covered_is_accepted(legitimate):
    report = accepted(build_context(**NONE_DECLARED), not_yet_verified=legitimate)

    assert len(report.ai_hypotheses) == 1, legitimate


def test_claiming_no_variables_are_declared_when_some_are_is_omitted():
    ctx = build_context(env=(("ALPHA_SETTING", "literal"),))

    report = accepted(
        ctx,
        not_yet_verified="No environment variables are declared and nothing "
        "else has been checked.",
    )

    assert report.ai_analysis.omission_reasons == {
        "contradicts_established_evidence": 1
    }


def test_claiming_a_variable_is_declared_when_none_are_is_omitted():
    ctx = build_context(**NONE_DECLARED)

    report = accepted(
        ctx,
        not_yet_verified="The variable is declared in the workload, but its "
        "value has not been verified.",
    )

    assert report.ai_analysis.omission_reasons == {
        "contradicts_established_evidence": 1
    }


def test_hedged_declaration_wording_is_not_a_contradiction():
    report = accepted(
        build_context(**NONE_DECLARED),
        not_yet_verified="Whether the variable is declared in some other "
        "source has not been verified.",
    )

    assert len(report.ai_hypotheses) == 1


@pytest.mark.parametrize(
    "overstated",
    [
        "The container has no environment variables and nothing else was checked.",
        "The environment is empty and nothing else was checked.",
    ],
)
def test_absence_of_a_declaration_is_not_proof_of_the_runtime_environment(overstated):
    report = accepted(build_context(**NONE_DECLARED), not_yet_verified=overstated)

    assert report.ai_hypotheses == []
    assert report.ai_analysis.omission_reasons == {"overstated_absence": 1}


@pytest.mark.parametrize(
    "disclaimer",
    [
        # Exact phrasing produced by the live model (regression).
        "The workload spec declares no environment variables, but this does "
        "not confirm the runtime environment is empty.",
        "The spec declares none, which cannot show that the environment is empty.",
        "Nothing here proves the environment is empty.",
    ],
)
def test_denying_the_inference_is_the_correct_wording_and_is_accepted(disclaimer):
    report = accepted(build_context(**NONE_DECLARED), not_yet_verified=disclaimer)

    assert len(report.ai_hypotheses) == 1, disclaimer


def test_a_declaration_statement_does_not_excuse_a_following_overstatement():
    report = accepted(
        build_context(**NONE_DECLARED),
        not_yet_verified="The spec declares no variables and the environment "
        "is empty, with nothing else checked.",
    )

    assert report.ai_analysis.omission_reasons == {"overstated_absence": 1}


def test_application_reported_requirements_are_not_checked_against_the_spec():
    # `reported` is an attributed application claim, not model uncertainty.
    report = accepted(
        build_context(**NONE_DECLARED),
        reported="no environment variables are declared for the service",
    )

    assert len(report.ai_hypotheses) == 1


def test_one_contradictory_hypothesis_does_not_discard_the_consistent_one():
    ctx = build_context(**NONE_DECLARED)
    refs = full_refs(snap(ctx))
    bad = model_hypothesis(
        evidence=refs,
        not_yet_verified="The workload configuration has not yet been inspected.",
    )
    good = model_hypothesis(evidence=refs)

    _, report = enrich(ctx, provider_returning(bad, good))

    assert len(report.ai_hypotheses) == 1
    assert report.ai_analysis.state == "generated"
    assert report.ai_analysis.hypotheses_omitted == 1


def test_consistency_failures_omit_wording_but_security_still_rejects_all():
    ctx = build_context(**NONE_DECLARED)
    refs = full_refs(snap(ctx))
    contradiction = model_hypothesis(
        evidence=refs,
        not_yet_verified="The workload configuration has not yet been inspected.",
    )
    unsafe = model_hypothesis(evidence=refs, verification_check="kubectl delete pod x")

    _, report = enrich(ctx, provider_returning(contradiction, unsafe))

    assert report.ai_analysis.state == "unavailable"
    assert report.ai_analysis.rejection_category == "security"


def test_deterministic_findings_are_untouched_by_hypothesis_handling():
    ctx = build_context(**NONE_DECLARED)
    base, report = enrich(
        ctx,
        provider_returning(
            model_hypothesis(
                evidence=full_refs(snap(ctx)),
                not_yet_verified="The workload configuration has not yet been inspected.",
            )
        ),
    )

    assert report.findings == base.findings
    assert report.summary == base.summary
    assert report.uncertainties == base.uncertainties


def test_model_input_carries_application_written_configuration_statements():
    ctx = build_context(**NONE_DECLARED)
    data = HypothesisInput(
        snapshot=snap(ctx),
        log_entries=ctx.log_entries,
        omitted_log_entries=0,
        authorized_namespace=NS,
    )

    system, user = build_hypothesis_messages(data)
    payload = json.loads(user["content"])
    [item] = payload["application_configuration_statements"]["items"]

    assert "declares no environment variables" in item["statement"]
    assert CONFIGURATION_SCOPE_NOTE in item["statement"]
    assert set(item["evidence_ids"]) <= {i.evidence_id for i in data.snapshot.evidence}
    assert "HAVE been inspected" in system["content"]
    assert "does not prove" in system["content"]


def test_enriched_report_still_holds_no_raw_log_text():
    report = accepted(build_context(**NONE_DECLARED))

    assert SENTINEL not in report.model_dump_json()


def test_report_flags_that_no_declaration_is_not_a_complete_environment():
    report = build_grounded_report(snap(build_context(**NONE_DECLARED)))

    assert any(
        "does not establish the complete runtime environment" in u
        for u in report.uncertainties
    )
    assert any(
        "does not establish the complete runtime environment" in c
        for c in report.suggested_checks
    )
    assert any(
        "not the complete runtime environment" in f.description
        for f in report.findings
    )


def test_declared_variables_do_not_trigger_the_no_declaration_caveat():
    report = build_grounded_report(snap(build_context()))

    assert not any(
        "no environment variables are declared" in u for u in report.uncertainties
    )


# ================================================== deterministic summary


def finding(title, severity, *evidence_ids, description="Something was observed."):
    return InvestigationFinding(
        title=title,
        description=description,
        severity=severity,
        evidence=[EvidenceReference(evidence_id=e) for e in evidence_ids],
    )


def test_corroborated_failure_leads_and_discovery_does_not():
    report = build_grounded_report(snap(build_context()))
    lines = report.summary.splitlines()
    numbered = [l for l in lines if l[:2] in {"1.", "2.", "3.", "4."}]

    # The crash-looping container is itself an established failure and now
    # leads (it was previously reported only as informational symptoms); the
    # corroborated startup-command finding remains among the top findings.
    assert "[critical] Container is crash-looping" in numbered[0]
    correlated = next(l for l in numbered if "unconditional exit" in l)
    assert "[warning]" in correlated
    assert "corroborated by independent evidence from pod state and workload configuration" in correlated
    assert not any("Pod discovered" in l for l in numbered)
    assert "observation count" not in report.summary
    assert "structured operational" not in report.summary


def test_summary_headline_reflects_scope_and_severity_mix():
    snapshot = snap(build_context())
    report = build_grounded_report(snapshot)
    first = report.summary.splitlines()[0]

    assert "namespace 'team-a'" in first
    assert f"{len(report.findings)} verified finding(s)" in first
    warnings = sum(f.severity == "warning" for f in report.findings)
    assert f"{warnings} warning" in first
    assert f"{len(snapshot.evidence)} trusted evidence item(s)" in first


def test_summary_preserves_evidence_references_and_uncertainties():
    snapshot = snap(build_context())
    report = build_grounded_report(snapshot)
    known = {i.evidence_id for i in snapshot.evidence}
    cited = {r.evidence_id for f in report.findings for r in f.evidence}
    import re

    shown = set(re.findall(r"ev-[0-9]{4}", report.summary))

    assert shown and shown <= known and shown <= cited
    top = report.findings[
        next(i for i, f in enumerate(report.findings) if f.severity == "warning")
    ]
    assert all(r.evidence_id in report.summary for r in top.evidence)
    assert f"{len(report.uncertainties)} uncertaint(ies) are recorded" in report.summary
    assert "underlying cause is not established" in report.summary


def test_summary_is_unchanged_by_ai_enrichment_and_never_adopts_ai_claims():
    ctx = build_context(**NONE_DECLARED)
    base, report = enrich(
        ctx,
        provider_returning(
            model_hypothesis(
                evidence=full_refs(snap(ctx)),
                reported="the service name zeta-marker-quux is wrong",
            )
        ),
    )

    assert report.ai_hypotheses
    assert report.summary == base.summary
    assert "zeta-marker-quux" not in report.summary
    assert "remain unverified" in report.summary


def test_summary_is_independent_of_workload_and_container_names():
    report = build_grounded_report(snap(build_context()))

    assert POD not in report.summary
    assert "main" in report.summary  # container names come from evidence only


def test_healthy_workload_reports_no_failure_as_corroborated():
    report = build_grounded_report(
        snap(build_context(ready=True, restarts=0, logs=None, config=False,
                           observed_exit=0))
    )

    assert "corroborated" not in report.summary
    assert "[warning]" not in report.summary


def test_empty_evidence_keeps_the_no_findings_message():
    ctx = InvestigationContext(
        investigation_id="inv-none", user_text="x", authorized_namespace=NS
    )
    report = build_grounded_report(
        __import__("app.reports.snapshot", fromlist=["x"])
        .build_investigation_evidence_snapshot(ctx)
    )

    assert report.summary.startswith("No supported operational findings")


def test_ranking_orders_by_severity_corroboration_abnormality_then_discovery():
    snapshot = snap(build_context())
    by = {(i.tool, i.field): i.evidence_id for i in snapshot.evidence}
    pods = by[("k8s.get_pods", "pods[].name")]
    exit_code = by[("k8s.describe_pod", "containers[main].last_termination.exit_code")]
    config = by[("k8s.describe_workload_config", "containers[main].image")]
    static = by[("k8s.describe_workload_config", "containers[main].startup.static_analysis")]

    findings = [
        finding("discovery", "info", pods),
        finding("config only", "info", config),
        finding("abnormal single", "info", exit_code),
        finding("corroborated info", "info", exit_code, static),
        finding("warning single", "warning", config),
        finding("critical", "critical", pods),
    ]

    order = [f.title for f, _, _ in rank_findings(findings, snapshot)]

    assert order == [
        "critical",
        "warning single",
        "corroborated info",
        "abnormal single",
        "config only",
        "discovery",
    ]


def test_routine_findings_never_displace_further_abnormal_evidence():
    snapshot = snap(build_context())
    by = {(i.tool, i.field): i.evidence_id for i in snapshot.evidence}
    logs = by[("k8s.get_logs", "logs.retrieved")]
    pods = by[("k8s.get_pods", "pods[].name")]
    abnormal = [
        by[("k8s.describe_pod", "containers[main].last_termination.exit_code")],
        by[("k8s.describe_pod", "containers[main].last_termination.reason")],
        by[("k8s.describe_pod", "containers[main].restart_count")],
        by[("k8s.describe_pod", "containers[main].ready")],
    ]
    findings = [finding("logs", "info", logs), finding("discovery", "info", pods)]
    findings += [finding(f"abnormal {i}", "info", e) for i, e in enumerate(abnormal)]

    summary = build_summary(findings, snapshot, [])

    for i in range(4):
        assert f"abnormal {i}" in summary
    assert "[info] logs" not in summary and "[info] discovery" not in summary


def test_summary_is_bounded_with_many_long_findings():
    snapshot = snap(build_context())
    ref = snapshot.evidence[0].evidence_id
    findings = [
        finding(f"t{i}", "warning", ref, description="Long sentence. " * 100)
        for i in range(120)
    ]

    summary = build_summary(findings, snapshot, ["u"] * 20)

    assert len(summary) <= 3000
    assert "116 further finding(s)" in summary


def test_summary_text_is_deterministic():
    snapshot = snap(build_context())

    assert (
        build_grounded_report(snapshot).summary
        == build_grounded_report(snapshot).summary
    )


# ============================== verification-check consistency (Step 1)

CHECK_CONFIGMAP = "Inspect the ConfigMap that supplies the setting through read-only describe output."
CHECK_SECRET = "Review the Secret referenced by the workload to see whether it holds the setting."


def check_report(ctx, check):
    refs = refs_available(snap(ctx))
    _, report = enrich(
        ctx, provider_returning(model_hypothesis(evidence=refs, verification_check=check))
    )
    return report


@pytest.mark.parametrize("check", [CHECK_CONFIGMAP, CHECK_SECRET,
                                   "Check the Secrets and ConfigMaps in the namespace for the setting."])
def test_check_inspecting_nonexistent_references_is_omitted(check):
    report = check_report(build_context(**NONE_DECLARED), check)

    assert report.ai_hypotheses == []
    assert report.ai_analysis.omission_reasons == {"check_contradicts_evidence": 1}
    assert report.ai_analysis.state == "all_omitted"


# Wording the model produces in live investigations. It checks the workload's
# own configuration and names ConfigMap/Secret only as examples of OTHER supply
# mechanisms, so it neither inspects nor verifies those resources: accepted.
CHECK_ILLUSTRATIVE_MENTION = (
    "Check the workload's configuration to confirm if PAYMENTS_DB_HOST is declared "
    "or if it is being supplied by another mechanism such as a ConfigMap or Secret."
)
# Wording that directs attention at the nonexistent references: omitted.
CHECK_VERIFY_EXISTENCE = (
    "Check the workload's configuration to see if it is intended to receive the "
    "PAYMENTS_DB_HOST variable from a ConfigMap or Secret, and verify if those "
    "resources exist and are correctly referenced."
)


@pytest.mark.parametrize(
    "check",
    [
        CHECK_VERIFY_EXISTENCE,
        "Confirm the setting is supplied from a ConfigMap.",
        "Look at the pod. Then verify the ConfigMap data.",  # second sentence only
        "Make sure the setting is defined. The Secret should exist in the namespace.",
    ],
)
def test_check_directing_attention_at_nonexistent_sources_is_omitted(check):
    report = check_report(build_context(**NONE_DECLARED), check)

    assert report.ai_hypotheses == []
    assert report.ai_analysis.omission_reasons == {"check_contradicts_evidence": 1}


@pytest.mark.parametrize(
    "check",
    [
        CHECK_ILLUSTRATIVE_MENTION,
        "Check the workload's configuration to confirm whether the environment variable "
        "is set and whether it is sourced from the correct location, such as a ConfigMap or Secret.",
        "Confirm with the workload owner how the setting is supplied, since the spec does not reference any ConfigMap.",
        "Note that no Secret is declared, so ask the owner of the Deployment manifest.",
    ],
)
def test_illustrative_negated_or_owner_directed_mentions_are_accepted(check):
    report = check_report(build_context(**NONE_DECLARED), check)

    assert len(report.ai_hypotheses) == 1, check


@pytest.mark.parametrize(
    "check", [CHECK_VERIFY_EXISTENCE, CHECK_ILLUSTRATIVE_MENTION]
)
def test_such_checks_are_fine_when_references_may_exist(check):
    for kwargs in (ENV_FROM, dict(env=(("ALPHA_SETTING", "secret_reference"),))):
        report = check_report(build_context(**kwargs), check)

        assert len(report.ai_hypotheses) == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        ENV_FROM,  # ConfigMap/Secret sources MAY exist: inspecting them is valid
        dict(env=(("ALPHA_SETTING", "secret_reference"),)),
        dict(config=False),  # configuration never inspected: nothing established
    ],
)
def test_same_check_is_fine_when_references_may_exist_or_are_unknown(kwargs):
    report = check_report(build_context(**kwargs), CHECK_CONFIGMAP)

    assert len(report.ai_hypotheses) == 1


@pytest.mark.parametrize(
    "check",
    [
        "Ask the workload owner how the Deployment manifest is intended to supply the setting.",
        "Review the deployment tooling that defines the workload to confirm the expected configuration mechanism.",
        "Confirm which source of truth defines the intended configuration for the service.",
    ],
)
def test_checks_about_the_intended_mechanism_are_accepted(check):
    report = check_report(build_context(**NONE_DECLARED), check)

    assert len(report.ai_hypotheses) == 1, check


@pytest.mark.parametrize(
    "check",
    [
        "Print the Secret value and compare it with the expected setting.",
        "Decode the base64 data of the Secret to confirm the setting.",
        "Read the contents of the Secret that holds the credential.",
        "Bypass RBAC authorization to read the resource.",
        "Use the cluster-admin kubeconfig to inspect the workload.",
        "Use a different kubeconfig with broader access to look at the workload.",
    ],
)
def test_checks_exposing_secrets_or_bypassing_authorization_reject_the_response(check):
    # Even with references that exist, this is a security failure.
    report = check_report(build_context(**ENV_FROM), check)

    assert report.ai_hypotheses == []
    assert report.ai_analysis.state == "unavailable"
    assert report.ai_analysis.rejection_category == "security"


def test_negated_secret_wording_is_not_treated_as_exposure():
    report = check_report(
        build_context(**ENV_FROM),
        "Confirm the Secret reference exists without revealing any Secret value.",
    )

    assert len(report.ai_hypotheses) == 1


def test_security_rejection_beats_consistency_omission_in_one_batch():
    ctx = build_context(**NONE_DECLARED)
    refs = refs_available(snap(ctx))
    inconsistent = model_hypothesis(evidence=refs, verification_check=CHECK_CONFIGMAP)
    unsafe = model_hypothesis(
        evidence=refs, verification_check="Dump the Secret value to a file."
    )

    _, report = enrich(ctx, provider_returning(inconsistent, unsafe))

    assert report.ai_analysis.state == "unavailable"
    assert report.ai_analysis.rejection_category == "security"


def test_one_inconsistent_check_does_not_discard_a_consistent_hypothesis():
    ctx = build_context(**NONE_DECLARED)
    refs = refs_available(snap(ctx))
    bad = model_hypothesis(evidence=refs, verification_check=CHECK_SECRET)
    good = model_hypothesis(evidence=refs)

    _, report = enrich(ctx, provider_returning(bad, good))

    assert len(report.ai_hypotheses) == 1
    assert report.ai_analysis.omission_reasons == {"check_contradicts_evidence": 1}


def test_application_check_points_at_the_owner_not_nonexistent_references():
    report = build_grounded_report(snap(build_context(**NONE_DECLARED)))
    [check] = [c for c in report.suggested_checks if "meant to be supplied" in c]

    assert "workload owner" in check and "Deployment manifest" in check
    assert "ConfigMap" not in check and "Secret" not in check


def test_prompt_directs_checks_at_the_intended_mechanism():
    from app.reports.qwen_hypotheses import HYPOTHESIS_SYSTEM_PROMPT

    prompt = " ".join(HYPOTHESIS_SYSTEM_PROMPT.split())

    assert "do not suggest inspecting them" in prompt
    assert "mention ConfigMaps or Secrets at all" in prompt
    assert "INTENDED to receive its configuration" in prompt
    assert "Ask the workload owner" in prompt
    assert "Never suggest reading Secret values" in prompt
