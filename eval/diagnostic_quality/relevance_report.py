"""Relevance metrics for saved benchmark arms.

    uv run python -m eval.diagnostic_quality.relevance_report \\
        closeout-revalidated relevance-replay-closeout relevance-final \\
        --scenarios all --out eval/results/diagnostic-quality/relevance-comparison.json

Every arm's saved records are graded by the same `relevance_rubric` (and the
same v2 + lifecycle graders the other reports use), so arms are comparable
whatever code produced them. Reported per arm:

  accepted_relevant / generic / irrelevant   by `relevance_rubric.classify`
  top_ranked_relevant                        the FIRST hypothesis the report
                                             displays, per run that has one
  relevant_rejected_for_validation           hypotheses graded relevant and
                                             rejected for a CONTENT reason
                                             (candidate false positives, to be
                                             reviewed by hand)
  wording_rejected                           rejected only for form (hedging,
                                             length, duplicates, citation count)

plus the headline numbers of `compare` (useful accepted, attribution errors,
latency, whole-response failures).
"""

import argparse
import json
from pathlib import Path

from eval.diagnostic_quality import relevance_rubric
from eval.diagnostic_quality.compare import load
from eval.diagnostic_quality.run import summarize
from eval.diagnostic_quality.scenarios import SCENARIOS

# Rejections of form, not of content.
WORDING_CODES = frozenset(
    {
        "insufficiently_cautious",
        "too_long",
        "too_many_references",
        "duplicate_hypothesis",
        "verified_claim",
    }
)


def relevance_block(records: list[dict]) -> dict:
    counts = {"relevant": 0, "generic": 0, "irrelevant": 0}
    irrelevant_accepted: list[dict] = []
    tops = {"relevant": 0, "generic": 0, "irrelevant": 0}
    top_runs = 0
    rejected_relevant: list[dict] = []
    wording = 0
    rejected_irrelevant = 0

    for record in records:
        scenario = record["scenario"]

        for item in record["accepted"]:
            graded = relevance_rubric.classify(scenario, item["raw"]["possible_explanation"])
            counts[graded["label"]] += 1

            if graded["label"] == "irrelevant":
                irrelevant_accepted.append(
                    {
                        "scenario": scenario,
                        "repeat": record["repeat"],
                        "text": item["raw"]["possible_explanation"],
                        "off_stage": graded["off_stage"],
                    }
                )

        if record["accepted"]:
            top_runs += 1
            top = relevance_rubric.classify(
                scenario, record["accepted"][0]["raw"]["possible_explanation"]
            )
            tops[top["label"]] += 1

        for entry in record["raw"]:
            if entry["outcome"] != "rejected":
                continue

            graded = relevance_rubric.classify(
                scenario, entry["raw"]["possible_explanation"]
            )

            if entry["code"] in WORDING_CODES:
                wording += 1
            elif graded["label"] == "relevant":
                rejected_relevant.append(
                    {
                        "scenario": scenario,
                        "repeat": record["repeat"],
                        "code": entry["code"],
                        "text": entry["raw"]["possible_explanation"],
                    }
                )
            elif graded["label"] == "irrelevant":
                rejected_irrelevant += 1

    accepted = sum(counts.values())

    return {
        "accepted_relevant": counts["relevant"],
        "accepted_generic": counts["generic"],
        "accepted_irrelevant": counts["irrelevant"],
        "irrelevant_share_of_accepted": round(counts["irrelevant"] / accepted, 3)
        if accepted
        else None,
        "runs_with_a_displayed_hypothesis": top_runs,
        "top_ranked_relevant": tops["relevant"],
        "top_ranked_generic": tops["generic"],
        "top_ranked_irrelevant": tops["irrelevant"],
        "top_ranked_relevant_rate": round(tops["relevant"] / top_runs, 3) if top_runs else None,
        "relevant_rejected_for_validation": len(rejected_relevant),
        "irrelevant_rejected_for_validation_or_wording": rejected_irrelevant,
        "wording_rejected": wording,
        "_irrelevant_accepted": irrelevant_accepted,
        "_relevant_rejected": rejected_relevant,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("labels", nargs="+")
    parser.add_argument("--scenarios", choices=["original", "all"], default="all")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    wanted = {s.id for s in SCENARIOS} if args.scenarios == "original" else None
    table = {}

    for label in args.labels:
        records = load(label, wanted)
        summary = summarize(records)
        headline = summary["headline"]
        table[label] = {
            "runs": summary["runs"],
            "proposed": headline["proposed"],
            "accepted": headline["accepted"],
            "useful_accepted_v2": headline["useful_accepted"],
            "accepted_with_technical_inaccuracy_v2": headline["accepted_with_technical_inaccuracy"],
            "evidence_attribution_errors_in_accepted": headline[
                "evidence_attribution_errors_in_accepted"
            ],
            "ai_latency_s_mean": headline["ai_stage_latency_s_mean"],
            "ai_latency_s_max": headline["ai_stage_latency_s_max"],
            "whole_response_failures": summary["validation"]["whole_response_failures"],
            **relevance_block(records),
        }

    public = [k for k in next(iter(table.values())) if not k.startswith("_")]
    width = max(len(k) for k in public)
    print(f"{'':{width}}  " + "  ".join(f"{label[:24]:>24}" for label in table))

    for key in public:
        print(f"{key:{width}}  " + "  ".join(f"{table[label][key]!s:>24}" for label in table))

    if args.out:
        args.out.write_text(json.dumps(table, indent=1))


if __name__ == "__main__":
    main()
