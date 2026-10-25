"""Live verification through the real API and the restricted investigator.

Starts the application on a loopback port with a THROWAWAY API key (never the
real one; the key exists only in this process' memory and its child's
environment), runs one investigation per lab workload, and saves each report.

    KUBECONFIG=~/.kube/private-ai-investigator.kubeconfig \\
        uv run python -m eval.diagnostic_quality.live

The Kubernetes identity must be the least-privilege ServiceAccount; the script
refuses to run otherwise. Nothing is changed in the cluster. The hypothesis
stage's exact inputs and raw outputs are recorded next to the reports.
"""

import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import httpx

OUT = Path(os.environ.get("DQ_LIVE_OUT", "eval/results/diagnostic-quality/live"))
PORT = 8097
NAMESPACE = "ai-ops-demo"
WORKLOADS = {
    "unschedulable": "impossible-pod",
    "image_pull": "broken-image",
    "oom_killed": "memory-hog",
    "running_not_ready": "bad-readiness",
    "liveness": "bad-liveness",
    # Restarted once, ready now, no probes (k8s/lab/eval-pod-level.yaml).
    "restart_history": "eval-past-restart",
    # Standalone Pods, no owner and no probes (k8s/lab/eval-relevance.yaml).
    "bare_crash": "eval-bare-crash",
    "bare_pull": "eval-bare-pull",
    "oom_recovered": "eval-oom-recovered",
    "bare_notready": "eval-bare-notready",
}


def _require_restricted_identity() -> None:
    from kubernetes import client as k8s

    from app.tools.kubernetes_client import load_kubernetes_config

    load_kubernetes_config()
    user = k8s.AuthenticationV1Api().create_self_subject_review(
        k8s.V1SelfSubjectReview()
    ).status.user_info.username

    if not user.startswith("system:serviceaccount:"):
        raise SystemExit("Refusing to run: the Kubernetes identity is not a ServiceAccount.")


def main() -> int:
    _require_restricted_identity()
    key = secrets.token_urlsafe(32)
    env = dict(os.environ)
    env["DQ_CAPTURE_DIR"] = str(OUT)
    OUT.mkdir(parents=True, exist_ok=True)
    env["PRIVATE_AI_API_KEYS_JSON"] = json.dumps(
        [
            {
                "principal_id": "dq-live-check",
                "key_sha256": hashlib.sha256(key.encode()).hexdigest(),
                "allowed_namespaces": [NAMESPACE],
            }
        ]
    )
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "eval.diagnostic_quality.live_app:app", "--host", "127.0.0.1", "--port", str(PORT)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        base = f"http://127.0.0.1:{PORT}"

        for _ in range(60):
            try:
                httpx.get(base + "/health", timeout=2)
                break
            except Exception:
                time.sleep(1)

        OUT.mkdir(parents=True, exist_ok=True)
        wanted = sys.argv[1:] or list(WORKLOADS)
        timings: dict[str, float] = {}

        with httpx.Client(base_url=base, headers={"X-API-Key": key}, timeout=300) as client:
            for label in wanted:
                workload = WORKLOADS[label]
                created = client.post(
                    "/investigations",
                    json={"question": f"Investigate why the {workload} workload is failing.", "namespace": NAMESPACE},
                ).json()
                iid = created["investigation_id"]
                started = time.monotonic()
                executed = client.post(f"/investigations/{iid}/execute")
                timings[label] = round(time.monotonic() - started, 2)
                report = client.get(f"/investigations/{iid}/report").json()
                (OUT / f"{label}.json").write_text(json.dumps(report, indent=1))
                print(label, executed.status_code, executed.json().get("status"), len(report.get("ai_hypotheses", [])), report.get("ai_analysis", {}).get("state"))
        (OUT / "timings.json").write_text(json.dumps(timings, indent=1))
    finally:
        server.terminate()
        server.wait(timeout=20)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
