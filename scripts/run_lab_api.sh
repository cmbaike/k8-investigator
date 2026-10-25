#!/usr/bin/env bash
# Start the API with the dedicated least-privilege investigator identity.
#
# Refuses to start if the Kubernetes identity the application would use is not
# a ServiceAccount (for example when it would silently fall back to an admin
# kubeconfig). Database settings must already be in the environment or .env.
# The console does not require an API key.
#
#   scripts/lab_investigator_kubeconfig.sh      # mint/refresh the kubeconfig
#   scripts/run_lab_api.sh                      # serve on 127.0.0.1:8080
set -euo pipefail

cd "$(dirname "$0")/.."

export KUBECONFIG="${INVESTIGATOR_KUBECONFIG:-$HOME/.kube/private-ai-investigator.kubeconfig}"
PYTHON="${PYTHON:-.venv/bin/python}"
HOST="${API_HOST:-0.0.0.0}"
PORT="${API_PORT:-8080}"

if [[ ! -f "$KUBECONFIG" ]]; then
  echo "Missing $KUBECONFIG. Run scripts/lab_investigator_kubeconfig.sh first." >&2
  exit 1
fi

"$PYTHON" - <<'PY'
import sys
from kubernetes import client
from app.tools.kubernetes_client import load_kubernetes_config

load_kubernetes_config()
user = client.AuthenticationV1Api().create_self_subject_review(
    client.V1SelfSubjectReview()
).status.user_info.username

if not user.startswith("system:serviceaccount:"):
    print("Refusing to start: Kubernetes identity is not a ServiceAccount.", file=sys.stderr)
    sys.exit(1)

print(f"Kubernetes identity: {user}")
PY

# No --reload: a presentation instance must not restart mid-investigation.
exec "$PYTHON" -m uvicorn app.api:app --host "$HOST" --port "$PORT"
