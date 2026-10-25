"""Diagnostic-quality benchmark for the AI hypothesis stage.

Runs the REAL Qwen model (or replays saved raw responses) on the controlled
scenarios in `scenarios.py`, grades every RAW model hypothesis with the fixed
rubric in `rubric.py`, and records what the application's validators decided.

    uv run python -m eval.diagnostic_quality.run --label after --repeats 2
    uv run python -m eval.diagnostic_quality.run --label after-replay \\
        --replay eval/results/diagnostic-quality/after

Measured separately (never combined into one score):

  technical     rubric errors among RAW hypotheses, and ESCAPES (rubric errors
                in hypotheses the application ACCEPTED)
  relevance     relevant / specific rates; top accepted hypothesis; distinct
                alternatives; coverage of independent constraints
  checks        relevant, read-only, scoped, technically clean
  validation    accepted, rejected by reason, whole-response failures, and
                CANDIDATE false-positive rejections (rejected although the
                rubric found no error, for manual review)
  operations    completion, tool coverage, added latency of the AI stage

A higher acceptance rate is NOT an improvement here: acceptance is reported
next to the escape rate, and only the latter says anything about accuracy.

Saved per run (so the same inputs can be given to another model or prompt):
  inputs/<scenario>.json        the exact messages sent to the model
  raw/<scenario>-<n>.json       the raw model response and its latency
  results.json                  every graded record
  summary.json                  the aggregated metrics
The rubric's SHA-256 is recorded with the results.
"""

import argparse
import hashlib
import json
import statistics
import sys
import time
from collections import Counter
from pathlib import Path

from app.reports.enrichment import add_ai_hypotheses
from app.reports.hypotheses import (
    MAX_HYPOTHESES,
    HypothesisEvidenceRegistry,
    HypothesisInput,
    HypothesisToneError,
    HypothesisValidationError,
    _is_duplicate,
    _ModelHypothesis,
    validate_hypothesis_fields,
)
from app.reports.qwen_hypotheses import (
    HYPOTHESIS_SYSTEM_PROMPT,
    QwenHypothesisProvider,
    build_hypothesis_messages,
)
from eval.diagnostic_quality import lifecycle_rubric, rubric
from eval.diagnostic_quality.scenarios import ALL_SCENARIOS, BY_ID, NS, build_cluster
from tests.pod_scenarios import investigate

RESULTS_ROOT = Path("eval/results/diagnostic-quality")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def rubric_hash() -> str:
    return sha256(Path(rubric.__file__).read_text())


def _hypothesis_input(ctx, snapshot) -> HypothesisInput:
    return HypothesisInput(
        snapshot=snapshot,
        log_entries=ctx.log_entries,
        omitted_log_entries=ctx.log_entries_omitted,
        authorized_namespace=NS,
    )


def classify_raw(content: str, registry: HypothesisEvidenceRegistry, investigation_id: str):
    """What the application decides about each RAW hypothesis, one by one.

    Mirrors `parse_hypothesis_response`, but records the outcome of every
    hypothesis instead of stopping at the first whole-response failure.
    Returns (items, whole_response_code)."""
    try:
        payload = json.loads(content)
        raw_items = payload["hypotheses"]
        assert isinstance(raw_items, list)
    except Exception:
        return [], "malformed_json"

    # The model must echo the investigation id exactly (a provenance check).
    if payload.get("investigation_id") != investigation_id:
        return [], "cross_investigation"

    if len(raw_items) > MAX_HYPOTHESES:
        return [], "hypothesis_count"

    items = []
    seen: set[str] = set()

    for index, raw in enumerate(raw_items):
        entry = {"index": index, "raw": raw, "outcome": "accepted", "code": None}

        try:
            parsed = _ModelHypothesis.model_validate(raw)
            validated = validate_hypothesis_fields(
                reported=parsed.reported,
                possible_explanation=parsed.possible_explanation,
                not_yet_verified=parsed.not_yet_verified,
                evidence=parsed.evidence,
                declared_resource=(
                    parsed.resource.model_dump() if parsed.resource else None
                ),
                verification_check=parsed.verification_check,
                registry=registry,
            )

            entry["check_withheld"] = validated.check_withheld_reason

            if _is_duplicate(validated, seen):
                entry.update(outcome="rejected", code="duplicate_hypothesis")
        except HypothesisToneError as exc:
            entry.update(outcome="rejected", code=exc.code)
        except HypothesisValidationError as exc:
            entry.update(outcome="whole_response", code=exc.code)
            items.append(entry)
            return items, exc.code
        except Exception:
            entry.update(outcome="whole_response", code="schema")
            items.append(entry)
            return items, "schema"

        items.append(entry)

    return items, None


def grade_hypothesis(raw: dict, scenario: rubric.Scenario) -> dict:
    text = " ".join(
        str(raw.get(k) or "") for k in ("possible_explanation", "not_yet_verified")
    )
    check = str(raw.get("verification_check") or "")
    technical = rubric.grade_text(text, scenario)
    relevance = rubric.grade_relevance(raw.get("possible_explanation") or "", scenario)
    check_grade = rubric.grade_check(check, scenario)

    return {
        "technical_errors": technical,
        # Lifecycle / memory-resource semantics (lifecycle_rubric.py).
        "lifecycle_errors": lifecycle_rubric.grade(text, scenario.id),
        "relevant": relevance["relevant"],
        "specific": relevance["specific"],
        "specific_families": relevance["specific_families"],
        "check": check_grade,
        "check_errors": rubric.grade_text(check, scenario),
    }


def _check_clean(grade: dict) -> bool:
    check = grade["check"]

    return not grade["check_errors"] and check["read_only"] and check["scoped"]


def _clean(grade: dict) -> bool:
    check = grade["check"]

    return (
        not grade["technical_errors"]
        and not grade.get("lifecycle_errors")
        and not grade["check_errors"]
        and grade["relevant"]
        and check["read_only"]
        and check["scoped"]
    )


def run_one(scenario: rubric.Scenario, repeat: int, provider, capture: dict) -> dict:
    cluster = build_cluster(scenario.id)
    ctx, snapshot, report, _ = investigate(cluster)
    data = _hypothesis_input(ctx, snapshot)
    messages = build_hypothesis_messages(data)
    registry = HypothesisEvidenceRegistry(
        investigation_id=ctx.investigation_id,
        authorized_namespace=NS,
        snapshot=snapshot,
        log_entries=ctx.log_entries,
    )
    capture.pop("content", None)
    capture.pop("attempts", None)
    started = time.monotonic()
    enriched = add_ai_hypotheses(report, snapshot=snapshot, context=ctx, provider=provider)
    latency = capture.get("saved_latency", time.monotonic() - started)
    content = capture.get("content")
    analysis = enriched.ai_analysis
    items, whole = (
        classify_raw(content, registry, ctx.investigation_id)
        if isinstance(content, str)
        else ([], "no_response")
    )

    graded = []

    for entry in items:
        grade = grade_hypothesis(entry["raw"], scenario)
        graded.append({**entry, "grade": grade})

    accepted = []

    for h in enriched.ai_hypotheses:
        raw = {
            "possible_explanation": h.possible_explanation,
            "not_yet_verified": h.not_yet_verified,
            "verification_check": h.verification_check,
        }
        grade = grade_hypothesis(raw, scenario)
        # A withheld check is never shown: it is graded by what the report
        # DISPLAYS (nothing), not by the model's original wording.
        accepted.append(
            {
                "raw": raw,
                "grade": grade,
                "check_shown": h.verification_check is not None,
                "check_withheld": h.check_withheld_reason,
            }
        )

    called = set(cluster.names)

    return {
        "scenario": scenario.id,
        "repeat": repeat,
        "latency_s": round(latency, 3),
        "model_attempts": len(capture.get("attempts") or []) or 1,
        "investigation_id": ctx.investigation_id,
        "analysis_state": analysis.state if analysis else None,
        "analysis_reason": analysis.reason if analysis else None,
        "whole_response_code": whole,
        "omission_reasons": dict(analysis.omission_reasons) if analysis else {},
        "tools_called": sorted(called),
        "tool_coverage": len(called & scenario.expected_tools) / len(scenario.expected_tools),
        "raw": graded,
        "accepted": accepted,
        "_messages": messages,
        "_content": content,
    }


def summarize(records: list[dict]) -> dict:
    scenarios = BY_ID
    raw = [(r, h) for r in records for h in r["raw"]]
    accepted = [(r, h) for r in records for h in r["accepted"]]

    def count_errors(pairs):
        counter: Counter[str] = Counter()

        for _, h in pairs:
            for e in h["grade"]["technical_errors"]:
                counter[e.split(":")[0]] += 1

        return dict(sorted(counter.items()))

    def rate(pairs, predicate):
        """Share of (record, hypothesis) pairs whose GRADE satisfies it."""
        if not pairs:
            return None

        return round(sum(1 for p in pairs if predicate(p[1]["grade"])) / len(pairs), 3)

    shown = [(r, h) for r, h in accepted if h.get("check_shown", True)]
    # Withheld checks are graded on the model's ORIGINAL wording (the record
    # of the proposal), since the accepted copy deliberately carries none.
    withheld = [(r, h) for r, h in raw if h.get("check_withheld")]
    tops = []

    for r in records:
        if r["accepted"]:
            tops.append((r, r["accepted"][0]))

    coverage = {}

    for r in records:
        s = scenarios[r["scenario"]]

        if s.multiple_constraints:
            families = {f for h in r["accepted"] for f in h["grade"]["specific_families"]}
            coverage[f"{r['scenario']}#{r['repeat']}"] = f"{len(families)}/{len(s.specific)}"

    rejected_reasons: Counter[str] = Counter()

    for _, h in raw:
        if h["outcome"] == "rejected":
            rejected_reasons[h["code"]] += 1

    candidate_fp = [
        {"scenario": r["scenario"], "repeat": r["repeat"], "code": h["code"], "raw": h["raw"]}
        for r, h in raw
        if h["outcome"] == "rejected" and _clean(h["grade"])
    ]
    escapes = [
        {"scenario": r["scenario"], "repeat": r["repeat"], "errors": h["grade"]["technical_errors"] + (h["grade"]["check_errors"] if h.get("check_shown", True) else []), "raw": h["raw"]}
        for r, h in accepted
        if h["grade"]["technical_errors"] or (h.get("check_shown", True) and h["grade"]["check_errors"])
    ]
    latencies = [r["latency_s"] for r in records]
    distinct_ok = [
        rubric.distinct([h["raw"]["possible_explanation"] for h in r["accepted"]]) == len(r["accepted"])
        for r in records
        if len(r["accepted"]) > 1
    ]

    attribution = {"state_attributed_to_logs", "log_claim_without_logs"}

    def errs(h):
        g = h["grade"]
        shown_check = g["check_errors"] if h.get("check_shown", True) else []

        return [e.split(":")[0] for e in g["technical_errors"]] + list(g.get("lifecycle_errors", [])) + shown_check

    def useful(h):
        g = h["grade"]

        return not errs(h) and g["relevant"] and (
            not h.get("check_shown", True) or (g["check"]["read_only"] and g["check"]["scoped"])
        )

    headline = {
        "proposed": len(raw),
        "accepted": len(accepted),
        "accepted_with_technical_inaccuracy": sum(1 for _, h in accepted if errs(h)),
        "accepted_technical_inaccuracies_by_type": dict(
            sorted(Counter(e for _, h in accepted for e in errs(h)).items())
        ),
        "false_positive_rejections_candidate": len(candidate_fp),
        "evidence_attribution_errors_in_accepted": sum(
            1 for _, h in accepted if attribution & set(errs(h))
        ),
        "evidence_attribution_errors_in_raw": sum(
            1
            for _, h in raw
            if attribution & {e.split(":")[0] for e in h["grade"]["technical_errors"]}
        ),
        "attribution_omissions_by_application": sum(
            1
            for _, h in raw
            if h["outcome"] == "rejected"
            and h["code"]
            in {
                "reported_without_log_evidence",
                "unattributed_log_claim",
                "misattributed_source",
                "unsupported_specific_claim",
            }
        ),
        "useful_accepted": sum(1 for _, h in accepted if useful(h)),
        "top_accepted_relevant_rate": rate(tops, lambda g: g["relevant"]),
        "ai_stage_latency_s_mean": round(statistics.mean(latencies), 2),
        "ai_stage_latency_s_max": round(max(latencies), 2),
    }

    return {
        "headline": headline,
        "lifecycle": {
            "raw_with_error": sum(1 for _, h in raw if h["grade"].get("lifecycle_errors")),
            "raw_errors_by_type": dict(
                sorted(Counter(e for _, h in raw for e in h["grade"].get("lifecycle_errors", [])).items())
            ),
            "accepted_with_error": sum(1 for _, h in accepted if h["grade"].get("lifecycle_errors")),
        },
        "rubric_version": rubric.RUBRIC_VERSION,
        "rubric_sha256": rubric_hash(),
        "runs": len(records),
        "technical": {
            "raw_hypotheses": len(raw),
            "raw_with_error": sum(1 for _, h in raw if h["grade"]["technical_errors"]),
            "raw_errors_by_type": count_errors(raw),
            "check_errors_in_raw": sum(1 for _, h in raw if h["grade"]["check_errors"]),
            "accepted_hypotheses": len(accepted),
            "escapes_accepted_with_error": len(escapes),
            "escape_rate": round(len(escapes) / len(accepted), 3) if accepted else None,
            "escapes": escapes,
        },
        "relevance": {
            "raw_relevant_rate": rate(raw, lambda g: g["relevant"]),
            "raw_specific_rate": rate(raw, lambda g: g["specific"]),
            "accepted_relevant_rate": rate(accepted, lambda g: g["relevant"]),
            "accepted_specific_rate": rate(accepted, lambda g: g["specific"]),
            "top_accepted_relevant": rate(tops, lambda g: g["relevant"]),
            "top_accepted_specific": rate(
                [t for t in tops if scenarios[t[0]["scenario"]].specific],
                lambda g: g["specific"],
            ),
            "runs_with_distinct_alternatives": (
                f"{sum(distinct_ok)}/{len(distinct_ok)}" if distinct_ok else None
            ),
            "multi_constraint_coverage": coverage,
        },
        "checks": {
            "raw_checks": len(raw),
            "raw_relevant": rate(raw, lambda g: g["check"]["relevant"]),
            "raw_not_read_only": sum(1 for _, h in raw if not h["grade"]["check"]["read_only"]),
            "raw_out_of_scope": sum(1 for _, h in raw if not h["grade"]["check"]["scoped"]),
            "raw_technically_unclean": sum(1 for _, h in raw if h["grade"]["check_errors"]),
            # Over checks the report actually SHOWS (withheld ones are not shown).
            "shown_checks": len(shown),
            "withheld_checks": len(withheld),
            "withheld_by_reason": dict(Counter(h["check_withheld"] for _, h in withheld)),
            "withheld_rubric_confirms_defect": sum(1 for _, h in withheld if not _check_clean(h["grade"])),
            "withheld_but_rubric_clean": sum(1 for _, h in withheld if _check_clean(h["grade"])),
            "accepted_relevant": rate(shown, lambda g: g["check"]["relevant"]),
            "accepted_not_read_only": sum(1 for _, h in shown if not h["grade"]["check"]["read_only"]),
            "accepted_out_of_scope": sum(1 for _, h in shown if not h["grade"]["check"]["scoped"]),
            "accepted_technically_unclean": sum(1 for _, h in shown if h["grade"]["check_errors"]),
        },
        "validation": {
            "proposed": len(raw),
            "accepted": sum(1 for _, h in raw if h["outcome"] == "accepted"),
            "rejected": sum(1 for _, h in raw if h["outcome"] == "rejected"),
            "rejected_by_reason": dict(sorted(rejected_reasons.items())),
            "whole_response_failures": sum(1 for r in records if r["whole_response_code"]),
            "whole_response_codes": dict(Counter(r["whole_response_code"] for r in records if r["whole_response_code"])),
            "candidate_false_positive_rejections": len(candidate_fp),
            "candidate_false_positives": candidate_fp,
        },
        "operations": {
            "runs_needing_a_second_model_attempt": sum(
                1 for r in records if r.get("model_attempts", 1) > 1
            ),
            "completion_rate": round(
                sum(1 for r in records if r["analysis_state"] in {"generated", "none_proposed", "all_omitted"}) / len(records), 3
            ),
            "analysis_states": dict(Counter(r["analysis_state"] for r in records)),
            "tool_coverage_mean": round(statistics.mean(r["tool_coverage"] for r in records), 3),
            "ai_stage_latency_s_mean": round(statistics.mean(latencies), 2),
            "ai_stage_latency_s_max": round(max(latencies), 2),
        },
        "per_scenario": {
            sid: {
                "runs": sum(1 for r in records if r["scenario"] == sid),
                "accepted": sum(len(r["accepted"]) for r in records if r["scenario"] == sid),
                "proposed": sum(len(r["raw"]) for r in records if r["scenario"] == sid),
                "whole_response_failures": sum(1 for r in records if r["scenario"] == sid and r["whole_response_code"]),
            }
            for sid in scenarios
            if any(r["scenario"] == sid for r in records)
        },
    }


def _capturing_completion(capture: dict):
    from app.llm import client

    def completion(**kwargs):
        response = client.chat.completions.create(**kwargs)
        capture["requested_id"] = json.loads(kwargs["messages"][1]["content"])[
            "investigation_id"
        ]

        try:
            capture["content"] = response.choices[0].message.content
        except Exception:
            capture["content"] = None

        # Every attempt is kept: the provider retries once after a purely
        # format-level whole-response failure.
        capture.setdefault("attempts", []).append(capture["content"])

        return response

    return completion


def _observation_keys(payload: dict) -> dict[str, tuple]:
    """Evidence id -> (tool, pod, field) for every observation in a payload."""
    keys = {}

    for section in ("kubernetes_verified_observations", "verified_configuration_evidence"):
        for item in (payload.get(section) or {}).get("items", []):
            keys[item["evidence_id"]] = (item["tool"], item["pod"], item["field"])

    return keys


def _remap_evidence(content: str, saved_inputs: dict | None, current: dict) -> str:
    """Re-express a saved response's evidence ids in the CURRENT snapshot.

    Evidence ids are positional: when the application mints one more
    observation (as the pod-level readiness-probe declaration does) every later
    id shifts by one, so a saved `ev-0017` would silently name another
    observation. Each id is therefore translated through what it NAMED
    (tool, pod, field), so the candidate outputs stay the same statements about
    the same observations. An id that names nothing in the current snapshot is
    left as is, and fails exactly as it would have."""
    if saved_inputs is None:
        return content

    old = _observation_keys(saved_inputs)
    new = {key: eid for eid, key in _observation_keys(current).items()}
    payload = json.loads(content)

    for hypothesis in payload.get("hypotheses", []):
        evidence = hypothesis.get("evidence")

        if isinstance(evidence, list):
            hypothesis["evidence"] = [
                new.get(old.get(ref), ref) if isinstance(ref, str) else ref
                for ref in evidence
            ]

    return json.dumps(payload)


def _replaying_completion(capture: dict, saved: dict, saved_inputs: dict | None = None):
    """Serve a saved raw response. Its investigation id is re-keyed to the
    current run's (random) id: the id is not part of what is graded. Evidence
    ids are translated to the current snapshot (see `_remap_evidence`)."""
    from types import SimpleNamespace

    def completion(**kwargs):
        capture["saved_latency"] = saved["latency_s"]
        current_payload = json.loads(kwargs["messages"][1]["content"])
        payload = json.loads(
            _remap_evidence(saved["content"], saved_inputs, current_payload)
        )
        current = current_payload["investigation_id"]
        requested = saved.get("requested_investigation_id")

        # A model that mis-copied the id in the original run must fail the
        # same way here (the id check rejects the whole response).
        payload["investigation_id"] = (
            "mis-copied-by-model"
            if requested is not None and payload.get("investigation_id") != requested
            else current
        )
        content = json.dumps(payload)
        capture["content"] = content

        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )

    return completion


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--label", required=True)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--scenario", action="append")
    parser.add_argument("--replay", help="directory of a previous run whose raw responses are re-graded")
    parser.add_argument("--out", default=str(RESULTS_ROOT))
    args = parser.parse_args(argv)

    out = Path(args.out) / args.label
    (out / "inputs").mkdir(parents=True, exist_ok=True)
    (out / "raw").mkdir(parents=True, exist_ok=True)
    selected = [BY_ID[s] for s in args.scenario] if args.scenario else list(ALL_SCENARIOS)
    records = []

    for scenario in selected:
        repeats = (
            len(list((Path(args.replay) / "raw").glob(f"{scenario.id}-*.json")))
            if args.replay
            else args.repeats
        )

        for repeat in range(repeats):
            capture: dict = {}

            if args.replay:
                source = Path(args.replay) / "raw" / f"{scenario.id}-{repeat}.json"
                inputs_file = Path(args.replay) / "inputs" / f"{scenario.id}.json"
                completion = _replaying_completion(
                    capture,
                    json.loads(source.read_text()),
                    json.loads(inputs_file.read_text())["payload"]
                    if inputs_file.exists()
                    else None,
                )
            else:
                completion = _capturing_completion(capture)

            provider = QwenHypothesisProvider(completion=completion, timeout=120)
            record = run_one(scenario, repeat, provider, capture)
            messages = record.pop("_messages")
            content = record.pop("_content")
            payload = json.loads(messages[1]["content"])

            if not args.replay:
                (out / "inputs" / f"{scenario.id}.json").write_text(
                    json.dumps(
                        {"scenario": scenario.id, "payload": payload}, indent=1, sort_keys=True
                    )
                )
                (out / "raw" / f"{scenario.id}-{repeat}.json").write_text(
                    json.dumps(
                        {
                            "content": content,
                            "model_attempts": record["model_attempts"],
                            "earlier_attempts": (capture.get("attempts") or [])[:-1],
                            "latency_s": record["latency_s"],
                            "requested_investigation_id": capture.get("requested_id"),
                        },
                        indent=1,
                    )
                )
            records.append(record)
            print(
                f"{scenario.id:18} #{repeat} state={record['analysis_state']:<12} "
                f"reason={record['analysis_reason'] or '-'} whole={record['whole_response_code'] or '-'} "
                f"proposed={len(record['raw'])} accepted={len(record['accepted'])} "
                f"{record['latency_s']:.1f}s",
                flush=True,
            )

    (out / "system_prompt.txt").write_text(HYPOTHESIS_SYSTEM_PROMPT)
    summary = summarize(records)
    summary["system_prompt_sha256"] = sha256(HYPOTHESIS_SYSTEM_PROMPT)
    summary["label"] = args.label
    summary["replay_of"] = args.replay
    (out / "results.json").write_text(json.dumps(records, indent=1, default=str))
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps({k: v for k, v in summary.items() if k not in {"per_scenario"}}, indent=1)[:6000])

    return 0


if __name__ == "__main__":
    sys.exit(main())
