"""Safe, read-only workload configuration summary.

Security policy (enforced by what this module can return):
  * Environment variable VALUES are never read into the result. Only names and
    SOURCE TYPES (literal / secret reference / ConfigMap reference / ...).
  * Startup commands and arguments are NEVER returned, stored, or audited.
    They may contain credentials. The only startup output is a small fixed
    vocabulary of structured facts, derived by a conservative static analysis
    that runs and discards the command text inside this module.
  * Annotations, labels, ConfigMap/Secret names and contents and volumes are
    not exposed. Probes are exposed ONLY as a bounded readiness-probe summary:
    its kind, port, a strictly validated path and numeric timings. Headers,
    hosts, exec commands, gRPC service names and every other probe field are
    never read into the result. (Annotations such as
    `kubectl.kubernetes.io/last-applied-configuration` embed the full spec.)
  * Hashing or truncating a command is NOT used: it would neither preserve
    diagnostic meaning nor guarantee confidentiality.

Identity is established by Kubernetes ownership references and UIDs
(Pod -> ReplicaSet -> Deployment), never by name patterns.
"""

import posixpath
import re
from typing import Any

WORKLOAD_CONFIG_TOOL = "k8s.describe_workload_config"

MAX_ENV_REPORTED = 25
MAX_ENV_SCANNED = 200
MAX_CONTAINERS = 10
MAX_STARTUP_SCRIPT_CHARS = 4096

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,252}$")
_CONTAINER_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,299}$")

ENV_NAME_PATTERN = _ENV_NAME
CONTAINER_NAME_PATTERN = _CONTAINER_NAME
IMAGE_PATTERN = _IMAGE

ENV_SOURCES = (
    "literal",
    "secret_reference",
    "config_map_reference",
    "field_reference",
    "resource_field_reference",
    "unknown",
)

ENTRYPOINT_KINDS = ("shell_script", "executable", "image_default")
STATIC_ANALYSES = ("unconditional_exit", "not_established")

_SHELLS = frozenset({"sh", "bash", "dash", "ash"})
# Commands with no control-flow effect and no dependence on the environment.
_INERT_COMMANDS = frozenset({"echo", "printf", "true", ":"})
# Unquoted characters that introduce expansion, redirection, pipelines,
# grouping, comments, assignment, globbing or history: all unsupported.
_UNSUPPORTED_UNQUOTED = frozenset("|&<>(){}$`\\!*?[]~#=%")
_QUOTED_EXPANSION = frozenset("$`\\")


PROBE_KINDS = ("http", "tcp", "exec", "grpc")
PROBE_PATH_PATTERN = re.compile(r"^/[A-Za-z0-9._~/\-]{0,100}$")
PORT_NAME_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,13}[a-z0-9])?$")
PROBE_TIMINGS = (
    "initial_delay_seconds",
    "period_seconds",
    "timeout_seconds",
    "failure_threshold",
)


def _bounded_int(value: Any, low: int = 0, high: int = 100_000) -> int | None:
    return value if type(value) is int and low <= value <= high else None


def summarize_probe(probe: Any) -> dict[str, Any]:
    """A bounded, non-sensitive summary of a probe declaration.

    Reads only: which handler kind, the target port, an http path that matches
    a strict character set (a path carrying a query string or anything else is
    omitted, not truncated) and four numeric timings. It never reads headers,
    host, scheme, exec commands or gRPC service names.
    """
    if probe is None:
        return {"declared": False}

    summary: dict[str, Any] = {"declared": True}
    http, tcp = getattr(probe, "http_get", None), getattr(probe, "tcp_socket", None)
    handler = http or tcp

    if http is not None:
        summary["kind"] = "http"
    elif tcp is not None:
        summary["kind"] = "tcp"
    elif getattr(probe, "_exec", None) is not None or getattr(probe, "exec", None) is not None:
        summary["kind"] = "exec"
    elif getattr(probe, "grpc", None) is not None:
        summary["kind"] = "grpc"

    port = getattr(handler, "port", None) if handler is not None else None

    if _bounded_int(port, 1, 65535) is not None:
        summary["port"] = port
    elif isinstance(port, str) and PORT_NAME_PATTERN.fullmatch(port):
        summary["port"] = port

    path = getattr(http, "path", None) if http is not None else None

    if isinstance(path, str) and PROBE_PATH_PATTERN.fullmatch(path):
        summary["path"] = path

    for name in PROBE_TIMINGS:
        value = _bounded_int(getattr(probe, name, None))

        if value is not None:
            summary[name] = value

    return summary


class WorkloadConfigError(RuntimeError):
    """Identity or ownership could not be verified. Message is safe to log."""


# --- startup behaviour (static analysis; command text never leaves here) ----


def _tokenize_simple_commands(script: str) -> list[list[str]] | None:
    """Split a script into simple commands, or None if it uses ANY construct
    beyond literal words separated by `;` or newlines."""
    if len(script) > MAX_STARTUP_SCRIPT_CHARS:
        return None

    commands: list[list[str]] = []
    words: list[str] = []
    current: list[str] = []
    in_word = False
    quote: str | None = None

    def end_word() -> None:
        nonlocal in_word
        if in_word:
            words.append("".join(current))
            current.clear()
            in_word = False

    def end_command() -> None:
        end_word()
        if words:
            commands.append(list(words))
            words.clear()

    for ch in script:
        if quote == "'":
            if ch == "'":
                quote = None
            else:
                current.append(ch)
            continue

        if quote == '"':
            if ch == '"':
                quote = None
            elif ch in _QUOTED_EXPANSION:
                return None
            else:
                current.append(ch)
            continue

        if ch in "'\"":
            quote = ch
            in_word = True
        elif ch in ";\n":
            end_command()
        elif ch in " \t\r":
            end_word()
        elif ch in _UNSUPPORTED_UNQUOTED:
            return None
        else:
            current.append(ch)
            in_word = True

    if quote is not None:
        return None

    end_command()
    return commands


def _static_exit_code(script: str) -> int | None:
    """Exit code if the script provably exits with a literal code after only
    inert, environment-independent commands. Otherwise None."""
    commands = _tokenize_simple_commands(script)

    if not commands:
        return None

    for command in commands:
        name = command[0]

        if name in _INERT_COMMANDS:
            continue

        if name == "exit":
            if len(command) == 2 and re.fullmatch(r"[0-9]{1,3}", command[1]):
                code = int(command[1])
                return code if code <= 255 else None
            return None

        return None

    return None


def analyze_startup(
    command: list[str] | None, args: list[str] | None
) -> dict[str, Any]:
    """Return ONLY fixed-vocabulary startup facts. Never the command or args.

    `static_analysis == "unconditional_exit"` means: the container's declared
    startup command is `<shell> -c <script>` and the script consists solely of
    inert literal commands followed by an explicit `exit <literal>`, with no
    expansion, branching, pipes or redirection. Its exit status therefore does
    not depend on environment variables or other inputs. Anything else (a
    different executable, an image-default entrypoint, any unsupported syntax)
    is `not_established`, which is not evidence either way.
    """
    command = [c for c in (command or []) if isinstance(c, str)]
    args = [a for a in (args or []) if isinstance(a, str)]

    result: dict[str, Any] = {
        "command_declared": bool(command),
        "args_declared": bool(args),
        "entrypoint_kind": "image_default",
        "static_analysis": "not_established",
        "static_exit_code": None,
    }

    if not command:
        return result

    result["entrypoint_kind"] = "executable"

    # `command` replaces the image ENTRYPOINT and `args` the image CMD.
    argv = command + args

    if (
        posixpath.basename(argv[0]) in _SHELLS
        and len(argv) >= 3
        and argv[1] == "-c"
    ):
        result["entrypoint_kind"] = "shell_script"
        code = _static_exit_code(argv[2])

        if code is not None:
            result["static_analysis"] = "unconditional_exit"
            result["static_exit_code"] = code

    return result


# --- environment (names and source types only) ------------------------------


def _env_source(env_var: Any) -> str:
    if getattr(env_var, "value", None) is not None:
        return "literal"

    value_from = getattr(env_var, "value_from", None)

    if value_from is None:
        return "unknown"

    if getattr(value_from, "secret_key_ref", None) is not None:
        return "secret_reference"

    if getattr(value_from, "config_map_key_ref", None) is not None:
        return "config_map_reference"

    if getattr(value_from, "field_ref", None) is not None:
        return "field_reference"

    if getattr(value_from, "resource_field_ref", None) is not None:
        return "resource_field_reference"

    return "unknown"


def summarize_environment(container: Any) -> dict[str, Any]:
    env_vars = list(getattr(container, "env", None) or [])
    env_from = list(getattr(container, "env_from", None) or [])

    names: list[dict[str, str]] = []
    seen: set[str] = set()

    for env_var in env_vars[:MAX_ENV_SCANNED]:
        name = getattr(env_var, "name", None)

        if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
            continue

        if name in seen:
            continue

        seen.add(name)
        names.append({"name": name, "source": _env_source(env_var)})

    return {
        "env_count": len(seen),
        "env": names[:MAX_ENV_REPORTED],
        "env_truncated": len(names) > MAX_ENV_REPORTED
        or len(env_vars) > MAX_ENV_SCANNED,
        # Variables loaded wholesale from a ConfigMap/Secret are invisible
        # without reading their contents, which is never done. The declared
        # name list is complete only when there are none.
        "env_names_complete": not env_from
        and len(env_vars) <= MAX_ENV_SCANNED,
    }


def safe_image(image: Any) -> str | None:
    """The one image validator shared by handler, extractor and report."""
    if (
        isinstance(image, str)
        and _IMAGE.fullmatch(image)
        and "://" not in image
        and not re.search(r"^[^/]*@[^/]*/", image)  # user:pass@host/ forms
    ):
        return image

    return None


# --- identity and assembly ---------------------------------------------------


def controller_reference(obj: Any, kind: str) -> tuple[str, str]:
    """(name, uid) of the single controlling owner of `kind`, or raise."""
    refs = [
        ref
        for ref in (getattr(obj.metadata, "owner_references", None) or [])
        if getattr(ref, "controller", False) is True
        and getattr(ref, "kind", None) == kind
    ]

    if len(refs) != 1 or not refs[0].name or not refs[0].uid:
        raise WorkloadConfigError(
            f"Resource is not controlled by exactly one {kind}."
        )

    return refs[0].name, refs[0].uid


def build_workload_config(
    *,
    namespace: str,
    pod: Any,
    replicaset: Any,
    deployment: Any,
) -> dict[str, Any]:
    """Assemble the safe summary from already-verified Kubernetes objects."""
    rs_name, rs_uid = controller_reference(pod, "ReplicaSet")

    if (
        replicaset.metadata.name != rs_name
        or replicaset.metadata.uid != rs_uid
        or replicaset.metadata.namespace != namespace
    ):
        raise WorkloadConfigError("ReplicaSet identity could not be verified.")

    dep_name, dep_uid = controller_reference(replicaset, "Deployment")

    if (
        deployment.metadata.name != dep_name
        or deployment.metadata.uid != dep_uid
        or deployment.metadata.namespace != namespace
    ):
        raise WorkloadConfigError("Deployment identity could not be verified.")

    selector = getattr(deployment.spec.selector, "match_labels", None) or {}
    pod_labels = pod.metadata.labels or {}

    if any(pod_labels.get(key) != value for key, value in selector.items()):
        raise WorkloadConfigError("Deployment selector does not match the pod.")

    containers = []

    for container in list(pod.spec.containers or [])[:MAX_CONTAINERS]:
        name = getattr(container, "name", None)

        if not isinstance(name, str) or not _CONTAINER_NAME.fullmatch(name):
            continue

        entry: dict[str, Any] = {
            "name": name,
            "image": safe_image(getattr(container, "image", None)),
            **summarize_environment(container),
            "readiness_probe": summarize_probe(
                getattr(container, "readiness_probe", None)
            ),
            "startup": analyze_startup(
                getattr(container, "command", None),
                getattr(container, "args", None),
            ),
        }
        containers.append(entry)

    status = deployment.status

    return {
        "namespace": namespace,
        "pod": pod.metadata.name,
        "workload": {
            "kind": "Deployment",
            "name": dep_name,
            "replicaset": rs_name,
            "ownership_verified": True,
            "desired_replicas": deployment.spec.replicas,
            "ready_replicas": getattr(status, "ready_replicas", None) or 0,
            "available_replicas": getattr(status, "available_replicas", None) or 0,
            "updated_replicas": getattr(status, "updated_replicas", None) or 0,
        },
        "containers": containers,
    }
