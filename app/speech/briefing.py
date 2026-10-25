"""Deterministic spoken briefing from an already validated report.

Presentation only. Outcome and evidence come from the finding the application
already ranked (highest severity, first among equals). One accepted hypothesis
may be spoken, still as a possibility. This module does not call a model, does
not score a new diagnosis, and does not read audit logs.
"""

import re

from app.reports.models import AIHypothesis, InvestigationFinding, InvestigationReport
from app.speech.sanitize import first_sentence, for_model_text, model_text_is_speakable

_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,62})$")
_SPEAKABLE_SEVERITY = {"critical": 0, "warning": 1, "unknown": 2}
_SECRET = re.compile(
    r"(?i)\b(?:api[_-]?key|password|passwd|secret|token|authorization|bearer|credential)"
    r"\b\s*[:=]\s*\S+"
)
_LONG_TOKEN = re.compile(r"\b(?:[A-Za-z0-9+/]{32,}={0,2}|[A-Fa-f0-9]{32,})\b")
_EVIDENCE_ID = re.compile(r"\b(?:ev|log)-\d{4}\b", re.IGNORECASE)
_CERTAIN = re.compile(r"\b(?:definitely|certainly|proven|verified|root cause)\b", re.IGNORECASE)
_EXIT = re.compile(r"\bexit code (\d{1,3})\b")
_RESTARTS = re.compile(r"\brestarted (\d+) time")
_LIMIT = re.compile(r"\bmemory limit of (\d+(?:\.\d+)?(?:Ki|Mi|Gi|Ti))\b")
_QUOTED = re.compile(r"'([A-Za-z0-9](?:[A-Za-z0-9_.-]{0,62})?)'")
_WORD = re.compile(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*")
# A following period or space ends the quantity. A following hyphen does not,
# so a name such as cache-32Mi-abc is left unchanged.
_QTY = re.compile(r"(?<![A-Za-z0-9_.-])(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti)(?![A-Za-z0-9_-])")
_GLUE = frozenset(
    """
    the and for that this with from have been were was its not but are has had
    into over than then next possible explanation container kubernetes pod
    deployment namespace reported recorded after before because while
    """.split()
)
_UNITS = {"Ki": "kibibytes", "Mi": "mebibytes", "Gi": "gibibytes", "Ti": "tebibytes"}
# Longer phrases first. "OOMKilled termination" must not become
# "out-of-memory kill termination". Names that continue through a hyphen,
# dot, or underscore are left unchanged.
_TERMS: tuple[tuple[str, str], ...] = (
    ("OOMKilled termination", "out-of-memory kill"),
    ("was OOMKilled", "was killed for running out of memory"),
    ("OOMKilled", "out-of-memory kill"),
    ("ImagePullBackOff", "image pull back-off"),
    ("ErrImagePull", "image pull error"),
    ("ErrImageNeverPull", "image never-pull"),
    ("CrashLoopBackOff", "crash loop back-off"),
    ("CreateContainerConfigError", "container configuration error"),
    ("CreateContainerError", "container creation error"),
    ("RunContainerError", "container start error"),
    ("ContainerCannotRun", "container start error"),
    ("InvalidImageName", "invalid image name"),
    ("ImageInspectError", "image inspect error"),
)
_CHECK_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?i)^retrieve the bounded application logs\b"),
        "Next, read the container's recent application logs.",
    ),
    (
        re.compile(r"(?i)^(?:read the event messages|review recent namespace events|retrieve the bounded kubernetes events)\b"),
        "Next, review the recent events for this pod.",
    ),
    (
        re.compile(r"(?i)^inspect the owning deployment's configuration\b"),
        "Next, inspect the Deployment's declared configuration.",
    ),
    (
        re.compile(r"(?i)^confirm that the\b.*\bimage\b"),
        "Next, compare the declared image reference with the registry's published tags.",
    ),
    (
        re.compile(r"(?i)^confirm that the readiness probe\b"),
        "Next, compare the readiness probe with the port and path the application serves.",
    ),
    (
        re.compile(r"(?i)^confirm that every volume declared\b"),
        "Next, confirm that each declared volume refers to an object that exists.",
    ),
)
_IMAGE_EVIDENCE = {
    "ImagePullBackOff": (
        "Kubernetes reports that pulling the image failed and is backing off before retrying"
    ),
    "ErrImagePull": "Kubernetes reports that pulling the image failed",
    "ErrImageNeverPull": (
        "Kubernetes reports that the image is not present on the node and the pull policy does not allow a pull"
    ),
    "InvalidImageName": "Kubernetes reports that the image reference is not valid",
    "ImageInspectError": "Kubernetes reports that the image could not be inspected",
}
_PRESTART_EVIDENCE = {
    "CreateContainerConfigError": "Kubernetes reports a container configuration error",
    "CreateContainerError": "Kubernetes reports a container creation error",
    "RunContainerError": "Kubernetes reports a container start error",
    "ContainerCannotRun": "Kubernetes reports a container start error",
}
_FAILURE = {
    "tool_failed": "A read-only Kubernetes call failed, so no report was produced.",
    "execution_failed": "Execution failed on the server, so no report was produced.",
    "execution_lease_expired": "The investigation stopped before it finished, so no report was produced.",
}
_EXPLANATION_WORDS = 28
_CHECK_WORDS = 18


def _safe_name(value: str | None) -> str | None:
    if value and _NAME.fullmatch(value):
        return value

    return None


def _sentence(text: str) -> str:
    text = " ".join(text.split()).strip()

    if not text:
        return ""

    return text if text[-1] in ".?" else f"{text}."


def _words(text: str) -> int:
    return len(_WORD.findall(text))


def _join(parts: list[str]) -> str:
    return " ".join(part for part in parts if part)


def _labeled(description: str, label: str) -> str | None:
    match = re.search(rf"\b{label} '([^']+)'", description, re.IGNORECASE)

    if not match:
        return None

    return _safe_name(match.group(1))


def _reason_tokens(text: str) -> list[str]:
    found = []

    for token, _spoken in _TERMS:
        if " " in token:
            continue

        if re.search(rf"(?<![A-Za-z0-9_.-]){re.escape(token)}(?![A-Za-z0-9_-])", text):
            found.append(token)

    if re.search(r"(?<![A-Za-z0-9_.-])Error(?![A-Za-z0-9_-])", text):
        found.append("Error")

    return found


def _normalize(text: str) -> str:
    """Pronounce known condition names and resource quantities.

    Exit codes stay digits, so speech says "137" rather than spelling each
    digit. Substitutions stop at identifier characters, so a hyphenated name
    is not rewritten.
    """

    def quantity(match: re.Match[str]) -> str:
        return f"{match.group(1)} {_UNITS[match.group(2)]}"

    text = _QTY.sub(quantity, text)

    for token, spoken in _TERMS:
        text = re.sub(
            rf"(?<![A-Za-z0-9_.-]){re.escape(token)}(?![A-Za-z0-9_-])",
            spoken,
            text,
        )

    text = re.sub(r"\btermination\s+termination\b", "termination", text, flags=re.IGNORECASE)
    text = re.sub(r"\bkill\s+kill\b", "kill", text, flags=re.IGNORECASE)

    return " ".join(text.split())


def _content_words(text: str) -> set[str]:
    return {word.lower() for word in _WORD.findall(text) if len(word) > 2 and word.lower() not in _GLUE}


def _adds_information(candidate: str, spoken: str) -> bool:
    return bool(_content_words(candidate) - _content_words(spoken))


def _clause(sentence: str) -> str:
    sentence = sentence.rstrip(".").strip()

    if sentence.startswith("The "):
        return "that the " + sentence[4:]

    if sentence.startswith("An "):
        return "that an " + sentence[3:]

    if sentence.startswith("A "):
        return "that a " + sentence[2:]

    if sentence[:1].isupper() and sentence[1:2].islower():
        return "that " + sentence[0].lower() + sentence[1:]

    return "that " + sentence


def _primary(findings: list[InvestigationFinding]) -> InvestigationFinding | None:
    best: tuple[int, int, InvestigationFinding] | None = None

    for index, finding in enumerate(findings):
        rank = _SPEAKABLE_SEVERITY.get(finding.severity)

        if rank is None:
            continue

        if best is None or (rank, index) < best[:2]:
            best = (rank, index, finding)

    return None if best is None else best[2]


def _coverage(report: InvestigationReport) -> str | None:
    for item in report.uncertainties:
        if not item.startswith("The requested "):
            continue

        if "could not be found" in item:
            return _sentence(
                "The requested workload could not be found. Nothing else was investigated"
            )

        if "matches more than one" in item:
            return _sentence(
                "The requested workload matches more than one workload, so none was investigated"
            )

        if "could not be resolved" in item or "were not listed" in item:
            return _sentence(
                "The requested workload could not be resolved. Nothing was investigated in its place"
            )

    return None


def _intact(original: str, cleaned: str) -> bool:
    def norm(text: str) -> str:
        return " ".join(first_sentence(text).split()).strip(" .")

    return bool(norm(cleaned)) and norm(original) == norm(cleaned)


def _tainted(text: str) -> bool:
    return (
        _SECRET.search(text) is not None
        or _LONG_TOKEN.search(text) is not None
        or _EVIDENCE_ID.search(text) is not None
        or _CERTAIN.search(text) is not None
    )


def _model_sentence(original: str, *, word_limit: int) -> str | None:
    if not original or not model_text_is_speakable(original) or _tainted(original):
        return None

    cleaned = for_model_text(original, limit=400)

    if not _intact(original, cleaned):
        return None

    sentence = _normalize(_QUOTED.sub(r"\1", first_sentence(cleaned)))

    if not sentence or _words(sentence) > word_limit:
        return None

    return sentence


def _explanation(hypothesis: AIHypothesis, spoken: str) -> str | None:
    sentence = _model_sentence(hypothesis.possible_explanation, word_limit=_EXPLANATION_WORDS)

    if sentence is None or not _adds_information(sentence, spoken):
        return None

    return _sentence(f"A possible explanation is {_clause(sentence)}")


def _mapped_check(original: str) -> str | None:
    if not original or not model_text_is_speakable(original) or _tainted(original):
        return None

    sentence = first_sentence(original)

    for pattern, spoken in _CHECK_PATTERNS:
        if pattern.search(sentence):
            return spoken

    return None


def _check_sentence(report: InvestigationReport) -> str | None:
    candidates: list[str] = []

    if report.ai_hypotheses and report.ai_hypotheses[0].verification_check:
        candidates.append(report.ai_hypotheses[0].verification_check or "")

    candidates.extend(report.suggested_checks)

    for original in candidates:
        mapped = _mapped_check(original)

        if mapped:
            return mapped

        sentence = _model_sentence(original, word_limit=_CHECK_WORDS)

        if sentence is None:
            continue

        sentence = re.sub(r"\s*\([^)]*\)", "", sentence).strip(" .")

        if not sentence or _words(sentence) > _CHECK_WORDS:
            continue

        if re.search(r"[:/\\]", sentence):
            continue

        if re.search(r"\b(?:tool|this report|evidence id|environment|secret)\b", sentence, re.IGNORECASE):
            continue

        if sentence.lower().startswith("next,") or sentence.lower().startswith("next "):
            return _sentence(sentence)

        clause = sentence[0].lower() + sentence[1:] if sentence[:1].isupper() and sentence[1:2].islower() else sentence

        return _sentence(f"Next, {clause.rstrip('.')}")

    return None


def _where(
    *,
    namespace: str,
    scope_mode: str,
    scope_kind: str | None,
    scope_name: str | None,
) -> str:
    safe_namespace = _safe_name(namespace)
    safe_name = _safe_name(scope_name)
    safe_kind = _safe_name(scope_kind)

    if scope_mode == "workload" and safe_name:
        return f"{safe_kind or 'workload'} {safe_name}"

    if safe_namespace and scope_mode == "namespace":
        return f"namespace {safe_namespace}"

    if safe_namespace:
        return f"namespace {safe_namespace}"

    return "the authorized namespace"


def _identity(
    finding: InvestigationFinding,
    *,
    namespace: str,
    scope_mode: str,
    scope_kind: str | None,
    scope_name: str | None,
    include_container: bool = True,
) -> str:
    """Customer-facing identity. Replica suffixes and the namespace stay in the report."""
    _ = namespace
    container = _labeled(finding.description, "container") if include_container else None
    pod = _labeled(finding.description, "pod")
    name = _safe_name(scope_name) if scope_mode == "workload" else None
    kind = _safe_name(scope_kind) if name else None

    controller = kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}

    if controller and name:
        if include_container and container and container != name:
            return f"Container {container} in {kind} {name}"

        return f"{kind} {name}"

    exact_pod = pod or (name if kind == "Pod" else None)

    if exact_pod and include_container and container and container != exact_pod:
        return f"Container {container} in pod {exact_pod}"

    if exact_pod:
        return f"Pod {exact_pod}"

    if name and include_container and container and container != name:
        return f"Container {container} in {kind or 'workload'} {name}"

    if name:
        return f"{kind or 'workload'} {name}"

    if container:
        return f"Container {container}"

    return "The workload"


def _scenario(finding: InvestigationFinding) -> str:
    title = finding.title
    reasons = _reason_tokens(f"{title}. {finding.description}")

    if "OOMKilled" in title:
        return "oom"

    if title == "Pod could not be scheduled":
        return "unschedulable"

    if "volume mount" in title.lower():
        return "volume"

    if title == "Container is running but not ready":
        return "readiness"

    if title == "Container is crash-looping" or (
        title == "Container failed at runtime" and "CrashLoopBackOff" in reasons
    ):
        return "crash"

    if title == "Container could not be started" and any(reason in _IMAGE_EVIDENCE for reason in reasons):
        return "image"

    if title == "Container could not be started":
        return "prestart"

    if "liveness" in title.lower():
        return "liveness"

    if title == "Container restarted earlier and is running now":
        return "restarted"

    return "generic"


def _oom(who: str, description: str) -> list[str]:
    reasons = _reason_tokens(description)
    exit_code = _EXIT.search(description)
    restarts = _RESTARTS.search(description)
    limit = _LIMIT.search(description)
    looping = "CrashLoopBackOff" in reasons

    if looping:
        outcome = f"{who} is crash-looping after it was killed for running out of memory"
    else:
        outcome = f"{who} was killed for running out of memory"

    recorded = []

    if exit_code and 0 <= int(exit_code.group(1)) <= 255:
        recorded.append(f"exit code {exit_code.group(1)}")

    if restarts and int(restarts.group(1)) >= 1 and not limit:
        count = int(restarts.group(1))
        recorded.append(f"{count} restart" + ("" if count == 1 else "s"))

    sentences = [_sentence(outcome)]

    if recorded:
        sentences.append(_sentence("Kubernetes recorded " + " after ".join(recorded)))

    if limit:
        sentences.append(
            _sentence(
                f"The configured memory limit is {limit.group(1)}. "
                "That is not a measurement of how much memory was used"
            )
        )
    elif "CrashLoopBackOff" in reasons and not looping:
        sentences.append(_sentence("The container is now in a crash loop back-off"))

    return sentences[:3]


def _image(who: str, description: str) -> list[str]:
    reason = next((item for item in _reason_tokens(description) if item in _IMAGE_EVIDENCE), None)
    evidence = _IMAGE_EVIDENCE.get(reason or "", "Kubernetes reports that the container has not started")

    return [
        _sentence(f"{who} has not started"),
        _sentence(evidence),
    ]


def _prestart(who: str, description: str) -> list[str]:
    reason = next((item for item in _reason_tokens(description) if item in _PRESTART_EVIDENCE), None)
    evidence = _PRESTART_EVIDENCE.get(reason or "", "Kubernetes reports it waiting")

    return [
        _sentence(f"{who} has not started"),
        _sentence(evidence),
    ]


def _crash(who: str, description: str) -> list[str]:
    reasons = _reason_tokens(description)
    sentences = [_sentence(f"{who} is crash-looping")]
    previous = next((reason for reason in reasons if reason != "CrashLoopBackOff"), None)

    if previous == "OOMKilled":
        sentences.append(_sentence("The previous termination was an out-of-memory kill"))
    elif previous:
        exit_code = _EXIT.search(description)
        extra = f", with exit code {exit_code.group(1)}" if exit_code and 0 <= int(exit_code.group(1)) <= 255 else ""
        sentences.append(_sentence(f"The previous termination reason was {previous}{extra}"))

    return sentences


def _unschedulable(who: str, finding: InvestigationFinding) -> list[str]:
    labels = [item.label for item in finding.scheduling_constraints]
    sentences = [
        _sentence(f"{who} could not be scheduled, so no container has run"),
    ]

    def spoken_label(label: str) -> str:
        if label[:1].isupper() and label[1:2].islower():
            return label[0].lower() + label[1:]

        return label

    if len(labels) == 1:
        sentences.append(_sentence(f"Kubernetes reported {spoken_label(labels[0])}"))
    elif len(labels) > 1:
        sentences.append(
            _sentence(
                f"Kubernetes reported {len(labels)} scheduling constraints, including {spoken_label(labels[0])}"
            )
        )
    else:
        sentences.append(
            _sentence("Kubernetes could not place the pod, and no scheduler constraint was classified")
        )

    return sentences


def _readiness(who: str) -> list[str]:
    return [
        _sentence(f"{who} is running but not ready"),
        _sentence(
            "Kubernetes reports the container running, and its readiness is false, so it is not receiving traffic"
        ),
    ]


def _volume(who: str) -> list[str]:
    return [
        _sentence(
            f"{who} was scheduled, but a container could not be created because a volume failed to mount"
        ),
        _sentence("Kubernetes recorded a volume mount failure, and no container ran"),
    ]


def _liveness(who: str) -> list[str]:
    return [
        _sentence(f"{who} was restarted after liveness probe failures"),
        _sentence(
            "Kubernetes recorded those probe failures for the pod. That does not establish why the probes failed"
        ),
    ]


def _restarted(who: str) -> list[str]:
    return [
        _sentence(f"{who} is running now"),
        _sentence("Kubernetes records an earlier restart. The cause of that restart is not established"),
    ]


def _generic(who: str, finding: InvestigationFinding) -> list[str]:
    title = _normalize(finding.title).rstrip(".")

    if title == "Container failed at runtime":
        return [
            _sentence(f"{who} failed after it started"),
            _sentence("Kubernetes reports the container not ready"),
        ]

    return [_sentence(f"{who}: {title[0].lower() + title[1:]}")]


def _condition(
    finding: InvestigationFinding,
    *,
    namespace: str,
    scope_mode: str,
    scope_kind: str | None,
    scope_name: str | None,
) -> list[str]:
    who = _identity(
        finding,
        namespace=namespace,
        scope_mode=scope_mode,
        scope_kind=scope_kind,
        scope_name=scope_name,
    )
    scenario = _scenario(finding)

    if scenario == "oom":
        sentences = _oom(who, finding.description)
    elif scenario == "image":
        sentences = _image(who, finding.description)
    elif scenario == "prestart":
        sentences = _prestart(who, finding.description)
    elif scenario == "crash":
        sentences = _crash(who, finding.description)
    elif scenario == "unschedulable":
        who = _identity(
            finding,
            namespace=namespace,
            scope_mode=scope_mode,
            scope_kind=scope_kind,
            scope_name=scope_name,
            include_container=False,
        )
        sentences = _unschedulable(who, finding)
    elif scenario == "readiness":
        sentences = _readiness(who)
    elif scenario == "volume":
        who = _identity(
            finding,
            namespace=namespace,
            scope_mode=scope_mode,
            scope_kind=scope_kind,
            scope_name=scope_name,
            include_container=False,
        )
        sentences = _volume(who)
    elif scenario == "liveness":
        sentences = _liveness(who)
    elif scenario == "restarted":
        sentences = _restarted(who)
    else:
        sentences = _generic(who, finding)

    return [_normalize(sentence) for sentence in sentences]


def _already_uncertain(sentences: list[str]) -> bool:
    text = _join(sentences).lower()

    return "not established" in text or "hasn't been confirmed" in text


def _uncertain() -> str:
    return _sentence("The underlying cause hasn't been confirmed")


def _partial() -> str:
    return _sentence("Coverage is incomplete because the read-only step budget was exhausted")


def build_spoken_briefing(
    *,
    status: str,
    stop_reason: str | None,
    namespace: str,
    scope_mode: str,
    scope_kind: str | None,
    scope_name: str | None,
    report: InvestigationReport | None,
) -> str:
    """A short incident briefing. Missing evidence stays missing."""
    where = _where(
        namespace=namespace,
        scope_mode=scope_mode,
        scope_kind=scope_kind,
        scope_name=scope_name,
    )

    if status == "failed":
        return _join(
            [
                _sentence(f"The investigation of {where} failed"),
                _sentence(_FAILURE.get(stop_reason or "", "No report was produced")),
                _sentence("No finding was established"),
            ]
        )

    if status in {"pending", "running"}:
        return _join(
            [
                _sentence(f"The investigation of {where} is still {status}"),
                _sentence("There is no finding yet"),
            ]
        )

    if status != "completed":
        return _join(
            [
                _sentence("The investigation status is not available"),
                _sentence("No finding was established"),
            ]
        )

    if report is None:
        return _join(
            [
                _sentence(f"The investigation of {where} finished without a report"),
                _sentence("No finding was established"),
            ]
        )

    coverage = _coverage(report)

    if coverage:
        sentences = [coverage]

        if stop_reason == "step_budget_exhausted":
            sentences.append(_partial())

        return _normalize(_join(sentences))

    finding = _primary(report.findings)

    if finding is None:
        sentences = [
            _sentence(
                f"The investigation of {where} did not establish a warning or critical problem"
            ),
            _uncertain(),
        ]
    else:
        sentences = _condition(
            finding,
            namespace=namespace,
            scope_mode=scope_mode,
            scope_kind=scope_kind,
            scope_name=scope_name,
        )
        explanation = _explanation(report.ai_hypotheses[0], _join(sentences)) if report.ai_hypotheses else None

        if explanation:
            sentences.append(explanation)
        elif not _already_uncertain(sentences):
            sentences.append(_uncertain())
        check = _check_sentence(report)

        if check:
            sentences.append(_normalize(check))

    if stop_reason == "step_budget_exhausted":
        sentences.append(_partial())

    return _join(sentences)
