"""Deterministic findings and uncertainties from workload-configuration evidence.

Everything here is derived from application-minted observations. No model
output, no command text and no environment values are involved (none exist in
the evidence). Findings are aggregated per container so a long list of
environment-variable names does not become one finding each.
"""

import re
from dataclasses import dataclass, field

from app.reports.models import EvidenceReference, InvestigationFinding
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.tools.workload_config import (
    CONTAINER_NAME_PATTERN,
    ENTRYPOINT_KINDS,
    ENV_NAME_PATTERN,
    ENV_SOURCES,
    PORT_NAME_PATTERN,
    PROBE_KINDS,
    PROBE_PATH_PATTERN,
    WORKLOAD_CONFIG_TOOL,
    safe_image,
)

_CONTAINER = CONTAINER_NAME_PATTERN.pattern.strip("^$")
_ENV = ENV_NAME_PATTERN.pattern.strip("^$")

_FIELD = re.compile(
    rf"^containers\[(?P<container>{_CONTAINER})\]\."
    rf"(?:(?P<attr>image|env\.count|env\.names_complete|"
    rf"readiness_probe\.(?:declared|kind|port|path|initial_delay_seconds|"
    rf"period_seconds|timeout_seconds|failure_threshold)|"
    rf"startup\.(?:entrypoint_kind|static_analysis|static_exit_code))"
    rf"|env\[(?P<env>{_ENV})\]\.source)$"
)

_EXIT_CODE_FIELD = re.compile(
    rf"^containers\[(?P<container>{_CONTAINER})\]\.last_termination\.exit_code$"
)

_ENV_SOURCE_LABELS = {
    "literal": "literal value",
    "secret_reference": "Secret reference",
    "config_map_reference": "ConfigMap reference",
    "field_reference": "field reference",
    "resource_field_reference": "resource-field reference",
    "unknown": "unknown source",
}

_ENTRYPOINT_LABELS = {
    "shell_script": "a custom shell-script startup command is declared",
    "executable": "a custom startup command is declared",
    "image_default": (
        "no startup command override is declared (the image default applies "
        "and was not inspected)"
    ),
}


@dataclass
class _ContainerConfig:
    attrs: dict[str, object] = field(default_factory=dict)
    refs: dict[str, str] = field(default_factory=dict)
    env: list[tuple[str, str, str]] = field(default_factory=list)


@dataclass
class _PodConfig:
    workload_name: str | None = None
    workload_refs: list[str] = field(default_factory=list)
    ownership_verified: bool = False
    containers: dict[str, _ContainerConfig] = field(default_factory=dict)


def collect_configuration(snapshot: InvestigationEvidenceSnapshot):
    pods: dict[tuple[str, str], _PodConfig] = {}
    exit_codes: dict[tuple[str, str, str], tuple[int, str]] = {}

    for item in snapshot.evidence:
        if not item.namespace or not item.pod:
            continue

        key = (item.namespace, item.pod)

        if item.tool == "k8s.describe_pod":
            match = _EXIT_CODE_FIELD.fullmatch(item.field)

            if (
                match
                and type(item.value) is int
                and 0 <= item.value <= 255
            ):
                exit_codes[(*key, match["container"])] = (
                    item.value,
                    item.evidence_id,
                )
            continue

        if item.tool != WORKLOAD_CONFIG_TOOL:
            continue

        pod = pods.setdefault(key, _PodConfig())

        if item.field == "workload.name" and isinstance(item.value, str):
            pod.workload_name = item.value
            pod.workload_refs.append(item.evidence_id)
            continue

        if item.field == "workload.ownership_verified":
            pod.ownership_verified = item.value is True
            pod.workload_refs.append(item.evidence_id)
            continue

        match = _FIELD.fullmatch(item.field)

        if match is None:
            continue

        container = pod.containers.setdefault(
            match["container"], _ContainerConfig()
        )

        if match["env"] is not None:
            if item.value in ENV_SOURCES:
                container.env.append(
                    (match["env"], item.value, item.evidence_id)
                )
            continue

        container.attrs[match["attr"]] = item.value
        container.refs[match["attr"]] = item.evidence_id

    return pods, exit_codes


def _suffix(namespace: str, pod: str, request_hint: str = "") -> str:
    return f" Resource: namespace {namespace!r}, pod {pod!r}."


def build_configuration_findings(
    snapshot: InvestigationEvidenceSnapshot,
) -> list[InvestigationFinding]:
    pods, exit_codes = collect_configuration(snapshot)
    findings: list[InvestigationFinding] = []

    for (namespace, pod_name), pod in pods.items():
        where = _suffix(namespace, pod_name)

        if pod.workload_name and pod.ownership_verified:
            findings.append(
                InvestigationFinding(
                    title="Owning workload identified",
                    description=(
                        f"Pod {pod_name!r} is controlled by Deployment "
                        f"{pod.workload_name!r}, verified through Kubernetes "
                        f"owner references and UIDs.{where}"
                    ),
                    severity="info",
                    evidence=[EvidenceReference(evidence_id=e) for e in pod.workload_refs],
                )
            )

        for name, config in pod.containers.items():
            findings.extend(
                _container_findings(
                    namespace, pod_name, name, config, where, exit_codes
                )
            )

    return findings


_TIMING_LABELS = (
    ("initial_delay_seconds", "initial delay {}s"),
    ("period_seconds", "period {}s"),
    ("timeout_seconds", "timeout {}s"),
    ("failure_threshold", "failure threshold {}"),
)


def describe_readiness_probe(
    config: "_ContainerConfig",
) -> tuple[str, list[str]] | None:
    """Validated, application-written statement of the declared readiness
    probe, with the evidence ids it rests on. None when probe configuration
    was not collected (it is then UNKNOWN, never assumed absent)."""
    attrs, refs = config.attrs, config.refs
    declared = attrs.get("readiness_probe.declared")

    if type(declared) is not bool:
        return None

    cited = [refs["readiness_probe.declared"]]

    if declared is False:
        return "declares no readiness probe", cited

    parts: list[str] = []
    kind = attrs.get("readiness_probe.kind")

    if kind in PROBE_KINDS:
        parts.append(f"{kind} handler")
        cited.append(refs["readiness_probe.kind"])

    port = attrs.get("readiness_probe.port")

    if (type(port) is int and 1 <= port <= 65535) or (
        isinstance(port, str) and PORT_NAME_PATTERN.fullmatch(port)
    ):
        parts.append(f"port {port}")
        cited.append(refs["readiness_probe.port"])

    path = attrs.get("readiness_probe.path")

    if isinstance(path, str) and PROBE_PATH_PATTERN.fullmatch(path):
        parts.append(f"path {path!r}")
        cited.append(refs["readiness_probe.path"])

    for key, label in _TIMING_LABELS:
        value = attrs.get(f"readiness_probe.{key}")

        if type(value) is int and 0 <= value <= 100_000:
            parts.append(label.format(value))
            cited.append(refs[f"readiness_probe.{key}"])

    return (
        "declares a readiness probe"
        + (f" ({', '.join(parts)})" if parts else ""),
        cited,
    )


def _container_findings(
    namespace, pod_name, name, config, where, exit_codes
) -> list[InvestigationFinding]:
    findings: list[InvestigationFinding] = []
    attrs, refs = config.attrs, config.refs

    parts: list[str] = []
    cited: list[str] = []

    image = safe_image(attrs.get("image"))

    if image is not None:
        parts.append(f"image {image!r}")
        cited.append(refs["image"])

    count = attrs.get("env.count")

    if type(count) is int and 0 <= count <= 10_000:
        cited.append(refs["env.count"])

        if config.env:
            listed = ", ".join(
                f"{env_name} ({_ENV_SOURCE_LABELS[source]})"
                for env_name, source, _ in config.env
            )
            cited.extend(ref for _, _, ref in config.env)
            parts.append(
                f"declares {count} environment variable(s) in its spec: {listed}"
            )
        elif count == 0 and attrs.get("env.names_complete") is True:
            parts.append(
                "declares no environment variables and no ConfigMap or Secret "
                "environment sources"
            )
        else:
            parts.append(f"declares {count} environment variable(s) in its spec")

        if attrs.get("env.names_complete") is False:
            cited.append(refs["env.names_complete"])
            parts.append(
                "additional variables may be loaded from ConfigMap or Secret "
                "references whose contents are not inspected"
            )

    probe = describe_readiness_probe(config)

    if probe is not None:
        parts.append(probe[0])
        cited.extend(probe[1])

    kind = attrs.get("startup.entrypoint_kind")

    if kind in ENTRYPOINT_KINDS:
        cited.append(refs["startup.entrypoint_kind"])
        parts.append(_ENTRYPOINT_LABELS[kind])

    if cited:
        findings.append(
            InvestigationFinding(
                title="Container configuration observed",
                description=(
                    f"Container {name!r}: "
                    + "; ".join(parts)
                    + ". Environment values and command text are never "
                    "collected, and this describes the declared spec only, "
                    f"not the complete runtime environment.{where}"
                )[:2000],
                severity="info",
                evidence=[EvidenceReference(evidence_id=e) for e in dict.fromkeys(cited)],
            )
        )

    code = attrs.get("startup.static_exit_code")

    if (
        attrs.get("startup.static_analysis") == "unconditional_exit"
        and type(code) is int
        and 0 <= code <= 255
    ):
        static_refs = [
            refs["startup.static_analysis"],
            refs["startup.static_exit_code"],
        ]
        findings.append(
            InvestigationFinding(
                title="Startup command exits unconditionally (static analysis)",
                description=(
                    f"Static analysis of container {name!r}'s declared "
                    "startup command found a shell script that runs only "
                    "literal output commands and then exits with code "
                    f"{code}, with no dependence on environment variables, "
                    "files or other inputs. This is a conservative "
                    "structural check, not a runtime observation; the "
                    f"command text is not collected.{where}"
                ),
                severity="info",
                evidence=[EvidenceReference(evidence_id=e) for e in static_refs],
            )
        )

        observed = exit_codes.get((namespace, pod_name, name))

        if observed is not None and observed[0] == code:
            findings.append(
                InvestigationFinding(
                    title="Observed exit code matches the startup command's unconditional exit",
                    description=(
                        f"Container {name!r} previously terminated with exit "
                        f"code {code} (reported by Kubernetes), and static "
                        "analysis of its startup command found an "
                        f"unconditional exit with the same code {code}. "
                        "Because that exit does not depend on environment "
                        "variables, changing environment variable values "
                        "alone would not be expected to change this "
                        f"termination.{where}"
                    ),
                    severity="warning",
                    evidence=[
                        EvidenceReference(evidence_id=observed[1]),
                        *[EvidenceReference(evidence_id=e) for e in static_refs],
                    ],
                )
            )

    return findings


def build_configuration_uncertainties(
    snapshot: InvestigationEvidenceSnapshot,
) -> list[str]:
    pods, _ = collect_configuration(snapshot)
    uncertainties: list[str] = []

    for (namespace, pod_name), pod in sorted(pods.items()):
        resource = f"Pod {pod_name!r} in namespace {namespace!r}"

        uncertainties.append(
            f"{resource}: environment variable values, ConfigMap contents "
            "and Secret contents are never inspected, so whether any "
            "variable is set correctly has not been established."
        )

        for name, config in sorted(pod.containers.items()):
            analysis = config.attrs.get("startup.static_analysis")

            if analysis == "not_established":
                uncertainties.append(
                    f"{resource}, container {name!r}: startup behavior "
                    "could not be established by static analysis. This is "
                    "not evidence that startup is correct."
                )

            if (
                config.attrs.get("env.count") == 0
                and config.attrs.get("env.names_complete") is True
            ):
                uncertainties.append(
                    f"{resource}, container {name!r}: no environment "
                    "variables are declared in its spec, which does not "
                    "establish the complete runtime environment (variables "
                    "may come from the image or other mechanisms)."
                )

            if config.attrs.get("env.names_complete") is False:
                uncertainties.append(
                    f"{resource}, container {name!r}: the environment "
                    "variable name list may be incomplete because variables "
                    "are also loaded from ConfigMap or Secret references."
                )

    return uncertainties


# --- deterministic configuration context for hypotheses ----------------------

CONFIGURATION_SCOPE_NOTE = (
    "This describes the declared workload spec only. Values, variables baked "
    "into the image and variables supplied by other mechanisms are not "
    "established, so it does not show the complete runtime environment."
)

MAX_CONTEXT_CONTAINERS = 3
MAX_CONTEXT_NAMES = 4
MAX_CONTEXT_REFS = 6
MAX_CONTEXT_CHARS = 1000


@dataclass(frozen=True)
class ConfigurationContext:
    """Application-authored statement of what a workload spec DECLARES.

    Four kinds of information are kept apart elsewhere in the report; this is
    only the first two:
      * declared:  variables (and ConfigMap/Secret sources) in the spec;
      * other mechanisms: explicitly NOT established (see the scope note).
    Application-reported requirements live in the hypothesis `reported` field
    and independently established termination in `independently_established`.
    """

    text: str
    refs: tuple[str, ...]
    # Facts the consistency check compares model wording against.
    inspected: bool
    declared_any: bool
    none_declared: bool  # no variables AND the name list is known complete
    startup_established: bool


def _container_statement(name: str, config, *, list_names: bool):
    attrs, refs = config.attrs, config.refs
    count = attrs.get("env.count")
    complete = attrs.get("env.names_complete")
    cited: list[str] = []

    if type(count) is not int or not 0 <= count <= 10_000:
        return None

    cited.append(refs["env.count"])

    if complete is not None:
        cited.append(refs["env.names_complete"])

    other = (
        " It also loads variables from ConfigMap or Secret references whose "
        "contents are not inspected."
        if complete is False
        else ""
    )

    if count == 0 and complete is True:
        body = (
            "declares no environment variables and no ConfigMap or Secret "
            "environment sources in its spec."
        )
    elif count == 0:
        body = "declares no individual environment variables in its spec."
    else:
        listing = ""

        if list_names and config.env:
            shown = config.env[:MAX_CONTEXT_NAMES]
            listing = ": " + ", ".join(
                f"{env} ({_ENV_SOURCE_LABELS[source]})"
                for env, source, _ in shown
            )
            cited.extend(ref for _, _, ref in shown)

            if len(config.env) > len(shown):
                listing += f", and {len(config.env) - len(shown)} more"

        body = f"declares {count} environment variable(s) in its spec{listing}."

    return f"Container {name!r} {body}{other}", cited, count, complete


def configuration_context_for(
    snapshot: InvestigationEvidenceSnapshot,
    namespace: str,
    pod: str | None,
    container: str | None = None,
) -> ConfigurationContext | None:
    """Deterministic declared-configuration statement for one resource, or
    None when the workload configuration was not inspected for it."""
    if pod is None:
        return None

    pods, exit_codes = collect_configuration(snapshot)
    config = pods.get((namespace, pod))

    if config is None or not config.containers:
        return None

    scope = {
        n: c
        for n, c in sorted(config.containers.items())
        if container is None or n == container
    }

    if not scope or len(scope) > MAX_CONTEXT_CONTAINERS:
        return None

    statements: list[str] = []
    refs: list[str] = []
    counts: list[int] = []
    completes: list[object] = []

    for name, cfg in scope.items():
        built = _container_statement(name, cfg, list_names=len(scope) == 1)

        if built is None:
            continue

        text, cited, count, complete = built
        statements.append(text)
        refs.extend(cited)
        counts.append(count)
        completes.append(complete)

    startup = any(
        cfg.attrs.get("startup.static_analysis") == "unconditional_exit"
        for cfg in scope.values()
    )

    if not statements:
        # Configuration was inspected but declarations were not observed.
        return ConfigurationContext(
            text="",
            refs=(),
            inspected=True,
            declared_any=False,
            none_declared=False,
            startup_established=startup,
        )

    refs = list(dict.fromkeys(refs))[:MAX_CONTEXT_REFS]
    text = " ".join([*statements, CONFIGURATION_SCOPE_NOTE])

    if len(text) > MAX_CONTEXT_CHARS:
        return ConfigurationContext(
            text="",
            refs=(),
            inspected=True,
            declared_any=any(c > 0 for c in counts),
            none_declared=False,
            startup_established=startup,
        )

    return ConfigurationContext(
        text=text,
        refs=tuple(refs),
        inspected=True,
        declared_any=any(c > 0 for c in counts),
        none_declared=all(c == 0 for c in counts)
        and all(c is True for c in completes),
        startup_established=startup,
    )
