"""Why does the model fill "reported" without citing a log?

Replays the exact hypothesis-stage inputs recorded by a live run, with prompt /
payload variants, and counts how often a hypothesis carries a non-null
"reported" without a log-NNNN id in its evidence (the case the application
discards as `reported_without_log_evidence`). Read-only; the model is the only
thing contacted.

    uv run python -m eval.diagnostic_quality.reported_probe \\
        --calls eval/results/diagnostic-quality/live-v2/hypothesis-calls.jsonl \\
        --samples 3 --out eval/results/diagnostic-quality/reported-probe.json
"""

import argparse
import json
import re
import time
from pathlib import Path

from app.llm import VLLM_MODEL, client
from app.reports.qwen_hypotheses import HYPOTHESIS_SYSTEM_PROMPT

_REPORTED_BLOCK = re.compile(
    r'- "reported": ONLY.*?(?=\n- "possible_explanation")', re.DOTALL
)


def prompt_with(reported_rule: str | None) -> str:
    if reported_rule is None:
        return HYPOTHESIS_SYSTEM_PROMPT

    assert _REPORTED_BLOCK.search(HYPOTHESIS_SYSTEM_PROMPT)

    return _REPORTED_BLOCK.sub(lambda _m: reported_rule.rstrip(), HYPOTHESIS_SYSTEM_PROMPT)


DECISION_RULE = """- "reported" is null in almost every hypothesis. It paraphrases what an
  APPLICATION LOG says and nothing else. Decide in this order:
  1. Does your "evidence" list contain a log-NNNN id? If NOT, "reported" MUST
     be null, even when logs exist. Focus groups never contain log ids.
  2. If it does, write a brief clause completing "The application logs report
     that ..." (do not repeat the lead-in) that paraphrases that log entry
     only. Do not restate it as fact.
  Kubernetes states, reasons, exit codes, restart counts, probe configuration
  and events (including "Liveness probe failed" and "Back-off restarting")
  are Kubernetes observations, never logs: cite their ev-NNNN ids and leave
  "reported" null. Despite its name, "reported" is not what Kubernetes
  reported.
  Wrong: "evidence": ["ev-0012"], "reported": "the container is restarting
  because the liveness probe fails". Right: "evidence": ["ev-0012"],
  "reported": null.
  If 'untrusted_logs' has no entries, "reported" MUST be null and you must not
  say or imply what any log contains."""

BALANCED_RULE = """- "reported" paraphrases what an APPLICATION LOG says, and nothing else.
  * If an entry in 'untrusted_logs' bears on the hypothesis, put its log_ref
    (log-NNNN) in "evidence" and set "reported" to a brief clause completing
    "The application logs report that ..." (do not repeat the lead-in) that
    paraphrases that entry only. Do not restate it as fact.
  * If no log entry bears on the hypothesis, cite none and "reported" MUST be
    null, even when logs exist. Focus groups never contain log ids, so a
    hypothesis copied from a focus group has "reported": null.
  A "reported" value without a log-NNNN id in "evidence" is discarded together
  with the hypothesis.
  Kubernetes states, reasons, exit codes, restart counts, probe configuration
  and events (including "Liveness probe failed" and "Back-off restarting")
  are Kubernetes observations, never logs, and never go in "reported": cite
  their ev-NNNN ids and say nothing about them there. Despite its name, "reported" is not what
  Kubernetes reported.
  Wrong: "evidence": ["ev-0012"], "reported": "the container is restarting
  because the liveness probe fails". Right: "evidence": ["ev-0012"],
  "reported": null.
  If 'untrusted_logs' has no entries, "reported" MUST be null and you must not
  say or imply what any log contains."""

BALANCED_RULE = """- "reported" paraphrases what an APPLICATION LOG says, and nothing else.
  * If an entry in 'untrusted_logs' bears on the hypothesis, put its log_ref
    (log-NNNN) in "evidence" and set "reported" to a brief clause completing
    "The application logs report that ..." (do not repeat the lead-in) that
    paraphrases that entry only. Do not restate it as fact.
  * If no log entry bears on the hypothesis, cite none and "reported" MUST be
    null, even when logs exist. Focus groups never contain log ids, so a
    hypothesis copied from a focus group has "reported": null.
  A "reported" value without a log-NNNN id in "evidence" is discarded together
  with the hypothesis.
  Kubernetes states, reasons, exit codes, restart counts, probe configuration
  and events (including "Liveness probe failed" and "Back-off restarting")
  are Kubernetes observations, never logs, and never go in "reported": cite
  their ev-NNNN ids and say nothing about them there. Despite its name, "reported" is not what
  Kubernetes reported.
  Wrong: "evidence": ["ev-0012"], "reported": "the container is restarting
  because the liveness probe fails". Right: "evidence": ["ev-0012"],
  "reported": null.
  If 'untrusted_logs' has no entries, "reported" MUST be null and you must not
  say or imply what any log contains."""

ARMS = {
    "current": (None, False),
    "decision_rule": (DECISION_RULE, False),
    "decision_rule_plus_log_refs": (DECISION_RULE, True),
    "balanced_plus_log_refs": (BALANCED_RULE, True),
}


def _payload_with_refs(user: str) -> str:
    data = json.loads(user)
    data["log_refs_available"] = [e["log_ref"] for e in data.get("untrusted_logs", [])]

    return json.dumps(data, ensure_ascii=True, separators=(",", ":"))


def classify(content: str) -> dict:
    try:
        hypotheses = json.loads(content)["hypotheses"]
    except Exception:
        return {"malformed": True, "hypotheses": 0, "reported_without_log": 0, "reported_with_log": 0}

    without = with_log = 0

    for h in hypotheses:
        cites_log = any(str(e).startswith("log-") for e in h.get("evidence") or [])

        if h.get("reported") and not cites_log:
            without += 1
        elif h.get("reported"):
            with_log += 1

    return {
        "malformed": False,
        "hypotheses": len(hypotheses),
        "reported_without_log": without,
        "reported_with_log": with_log,
    }


def run(calls: Path, samples: int, temperature: float, arms: list[str]) -> dict:
    inputs = [json.loads(line) for line in calls.read_text().splitlines()]
    results: dict[str, list] = {name: [] for name in arms}

    for index, call in enumerate(inputs):
        user = next(m["content"] for m in call["messages"] if m["role"] == "user")
        has_logs = bool(json.loads(user).get("untrusted_logs"))

        for name in arms:
            rule, refs = ARMS[name]
            messages = [
                {"role": "system", "content": prompt_with(rule)},
                {"role": "user", "content": _payload_with_refs(user) if refs else user},
            ]

            for sample in range(samples):
                started = time.monotonic()
                response = client.chat.completions.create(
                    model=VLLM_MODEL,
                    messages=messages,
                    temperature=0 if sample == 0 else temperature,
                    max_tokens=1500,
                    timeout=60,
                    extra_body={"chat_template_kwargs": {"enable_thinking": False}},
                )
                content = response.choices[0].message.content
                results[name].append(
                    {
                        "call": index,
                        "has_logs": has_logs,
                        "sample": sample,
                        "latency_s": round(time.monotonic() - started, 2),
                        "content": content,
                        **classify(content),
                    }
                )

    return results


def summarise(results: dict) -> dict:
    out = {}

    for name, rows in results.items():
        for scope, selected in (
            ("with_logs", [r for r in rows if r["has_logs"]]),
            ("without_logs", [r for r in rows if not r["has_logs"]]),
        ):
            out[f"{name}/{scope}"] = {
                "responses": len(selected),
                "hypotheses": sum(r["hypotheses"] for r in selected),
                "reported_without_log": sum(r["reported_without_log"] for r in selected),
                "reported_with_log": sum(r["reported_with_log"] for r in selected),
                "malformed": sum(r["malformed"] for r in selected),
            }

    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--calls", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--temperature", type=float, default=0.4)
    parser.add_argument("--arms", nargs="+", default=list(ARMS), choices=list(ARMS))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    results = run(args.calls, args.samples, args.temperature, args.arms)
    summary = summarise(results)
    args.out.write_text(json.dumps({"summary": summary, "results": results}, indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
