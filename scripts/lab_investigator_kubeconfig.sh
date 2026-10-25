#!/usr/bin/env bash
# Mint a kubeconfig for the dedicated, least-privilege investigator identity.
#
# Uses the CURRENT kubectl context (an administrator) only to request a
# short-lived, audience-bound ServiceAccount token. The generated file holds
# the cluster CA and that token only: no admin certificates or keys.
#
#   scripts/lab_investigator_kubeconfig.sh [output-path]
#   KUBECONFIG=<output-path> uvicorn app.api:app ...
#
# The token is never printed. Re-run before it expires (default 12h).
set -euo pipefail

NAMESPACE="${INVESTIGATOR_NAMESPACE:-ai-ops-demo}"
SERVICE_ACCOUNT="${INVESTIGATOR_SERVICE_ACCOUNT:-private-ai-investigator}"
DURATION="${INVESTIGATOR_TOKEN_DURATION:-12h}"
OUTPUT="${1:-$HOME/.kube/private-ai-investigator.kubeconfig}"

umask 077

CLUSTER_NAME="$(kubectl config view --minify -o jsonpath='{.clusters[0].name}')"
SERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
CA_DATA="$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"

if [[ -z "$CA_DATA" ]]; then
  echo "Current cluster has no embedded certificate-authority-data; aborting." >&2
  exit 1
fi

TOKEN="$(kubectl create token "$SERVICE_ACCOUNT" -n "$NAMESPACE" --duration="$DURATION")"

TMP="$(mktemp "${OUTPUT}.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: ${CLUSTER_NAME}
    cluster:
      server: ${SERVER}
      certificate-authority-data: ${CA_DATA}
users:
  - name: ${SERVICE_ACCOUNT}
    user:
      token: ${TOKEN}
contexts:
  - name: ${SERVICE_ACCOUNT}@${CLUSTER_NAME}
    context:
      cluster: ${CLUSTER_NAME}
      user: ${SERVICE_ACCOUNT}
      namespace: ${NAMESPACE}
current-context: ${SERVICE_ACCOUNT}@${CLUSTER_NAME}
EOF

mv "$TMP" "$OUTPUT"
trap - EXIT
chmod 600 "$OUTPUT"

echo "Wrote ${OUTPUT} (identity: system:serviceaccount:${NAMESPACE}:${SERVICE_ACCOUNT}, token valid ${DURATION})."
