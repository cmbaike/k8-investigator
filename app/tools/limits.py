TOOL_TIMEOUT_SECONDS = 10.0
MAX_TOOL_OUTPUT_BYTES = 64 * 1024

K8S_LIST_PAGE_SIZE = 100
K8S_LOG_LIMIT_BYTES = 32 * 1024

# Events: a pod-bound listing is further capped before it leaves the handler.
# Messages are untrusted free text: they are truncated here and never become
# evidence (see app/tools/observations.py).
K8S_EVENT_MAX_ITEMS = 50
K8S_EVENT_MESSAGE_MAX_CHARS = 300