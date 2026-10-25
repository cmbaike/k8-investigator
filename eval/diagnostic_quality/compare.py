"""Side-by-side headline metrics for saved benchmark arms.

Re-grades EVERY arm's saved records with the same graders (the frozen v2
rubric's grades are reused as saved; the lifecycle graders are applied to the
saved text, so arms produced before they existed are comparable), optionally
restricted to a set of scenarios.

    uv run python -m eval.diagnostic_quality.compare \\
        baseline arm-b closeout-replay-arm-b closeout \\
        --scenarios original --out eval/results/diagnostic-quality/closeout-comparison.json
"""

import argparse
import json
from pathlib import Path

from eval.diagnostic_quality import lifecycle_rubric
from eval.diagnostic_quality.run import RESULTS_ROOT, summarize
from eval.diagnostic_quality.scenarios import SCENARIOS


def _regrade(records: list[dict]) -> list[dict]:
    for record in records:
        for key in ("raw", "accepted"):
            for item in record[key]:
                raw = item["raw"]
                text = " ".join(
                    str(raw.get(k) or "") for k in ("possible_explanation", "not_yet_verified")
                )
                item["grade"]["lifecycle_errors"] = lifecycle_rubric.grade(
                    text, record["scenario"]
                )

    return records


def load(label: str, scenarios: set[str] | None) -> list[dict]:
    records = json.loads((RESULTS_ROOT / label / "results.json").read_text())

    if scenarios is not None:
        records = [r for r in records if r["scenario"] in scenarios]

    return _regrade(records)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("labels", nargs="+")
    parser.add_argument("--scenarios", choices=["original", "all"], default="original")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    wanted = {s.id for s in SCENARIOS} if args.scenarios == "original" else None
    table = {}

    for label in args.labels:
        records = load(label, wanted)
        summary = summarize(records)
        table[label] = {
            "runs": summary["runs"],
            **summary["headline"],
            "raw_with_v2_error": summary["technical"]["raw_with_error"],
            "raw_with_lifecycle_error": summary["lifecycle"]["raw_with_error"],
            "raw_lifecycle_errors_by_type": summary["lifecycle"]["raw_errors_by_type"],
            "whole_response_failures": summary["validation"]["whole_response_failures"],
            "rejected_by_reason": summary["validation"]["rejected_by_reason"],
        }

    keys = list(next(iter(table.values())))
    width = max(len(k) for k in keys)
    print(f"{'':{width}}  " + "  ".join(f"{label[:22]:>22}" for label in table))

    for key in keys:
        cells = []

        for label in table:
            value = table[label][key]
            cells.append(f"{json.dumps(value) if isinstance(value, dict) else value!s:>22}"[:22])

        print(f"{key:{width}}  " + "  ".join(cells))

    if args.out:
        args.out.write_text(json.dumps(table, indent=1))


if __name__ == "__main__":
    main()
