"""Additional grading axes (v3-additive): lifecycle and memory-resource semantics.

`rubric.py` (v2) is frozen and its hash is recorded with every earlier result,
so these graders live beside it instead of in it. They grade the SAME raw text,
are applied identically to every arm (including the earlier ones, from their
saved outputs), and import nothing from `app.reports`.

Independence is limited and should be read as such: the graders and the
application's new rules were written in the same sitting, from the same list of
defects. Each grader is deliberately simpler than the rule it audits (no
quotation handling beyond stripping, one denial test per sentence), so
"the validator accepted it" and "it was wrong" remain separate measurements,
but a defect neither anticipated is invisible to both.

Errors (each True when the text commits the error):

  never_started_but_ran           says a container that is running, or that
                                  Kubernetes records as restarted, never
                                  started
  request_blamed_for_oom          makes a memory REQUEST the cause of an OOM
                                  kill (the limit, or node pressure, is)
  request_limit_role_confusion    request as a ceiling; exceeding the request
                                  as what kills; the limit as a reservation
  restart_count_proves_cause      restart history stated as proof of a cause
  restart_count_shows_failure_now restart history stated as a CURRENT failure
                                  of a container that is ready now
  not_ready_but_ready             calls a container that is ready now "not
                                  ready" (earlier not-readiness is history)
"""

import re

_I = re.IGNORECASE

# Scenarios where the container is running now / is recorded as having run.
RUNNING_NOW = frozenset(
    {"running_not_ready", "liveness_failure", "healthy", "restart_history", "oom_recovered"}
)
RAN_BEFORE = RUNNING_NOW | {"oom_killed", "crash_loop"}
READY_NOW = frozenset({"liveness_failure", "healthy", "restart_history", "oom_recovered"})

_DENIAL = re.compile(r"\b(?:not|no|never|cannot|without|unable|whether|rather\s+than|instead\s+of)\b|n't", _I)
_HEDGE = re.compile(r"\b(?:may|might|could|possibly|perhaps|potentially|whether|if|unless)\b", _I)

_NOT_STARTED = re.compile(
    r"\bnever\s+(?:started|began|ran|launched)\b"
    r"|\b(?:fail\w*|unable)\s+to\s+(?:start|initiali[sz]e|boot|come\s+up)\b"
    r"|\b(?:did\s+not|didn't|has\s+not|hasn't)\s+(?:ever\s+|yet\s+)?(?:start|started|launch|run)\b",
    _I,
)
_OOM = r"(?:oom\w*|out[\s-]of[\s-]memory)"
_REQUEST_ROLE = [
    re.compile(r"\bmemory\s+requests?\b[^.;]{0,40}\b(?:maximum|max|caps?|ceiling|upper\s+bound)\b", _I),
    re.compile(r"\bexceed\w*\s+(?:its|the)\s+(?:memory\s+)?requests?\b[^.;]{0,60}\b(?:kill\w*|oom\w*|terminat\w*)\b", _I),
    re.compile(r"\b(?:kill\w*|oom\w*|terminat\w*)\b[^.;]{0,60}\bexceed\w*\s+(?:its|the)\s+(?:memory\s+)?requests?\b", _I),
    re.compile(r"\bmemory\s+limits?\b[^.;]{0,40}\b(?:guarantee\w*|reserv\w*)\b", _I),
]
_RESTARTS = r"(?:restarts?|restart\s+count|restarted)"
_PROVES = re.compile(rf"\b{_RESTARTS}\b[^.;]{{0,50}}\b(?:prove\w*|confirm\w*|demonstrat\w*|establish\w*)\b", _I)
_NOT_READY = re.compile(r"\b(?:is|are|be|being|marked|reported|remains?|but|currently)\s+(?:\w+\s+)?not\s+(?:yet\s+)?ready\b|\bunready\b", _I)
_PAST = re.compile(r"\b(?:earlier|previous\w*|before|history|formerly|originally|briefly|initially)\b", _I)
_SHOWS_FAILURE_NOW = re.compile(
    rf"\b{_RESTARTS}\b[^.;]{{0,40}}\b(?:show\w*|indicat\w*|mean\w*|impl\w*|prove\w*)\b[^.;]{{0,20}}"
    r"\b(?:it|container|pod|application)\s+(?:is|are|keeps?|remains?)\s+(?:still\s+|currently\s+|now\s+)?"
    r"(?:failing|crash\w*|restarting|unhealthy|broken)\b",
    _I,
)


def _plain(text: str) -> str:
    return " ".join(re.sub(r"\"[^\"]*\"|\u201c[^\u201d]*\u201d", " ", text).split())


def _sentences(text: str) -> list[str]:
    return re.split(r"(?<=[.!?])\s+", text)


def _asserts(pattern: re.Pattern[str], sentence: str, *, excuse: re.Pattern[str]) -> bool:
    for match in pattern.finditer(sentence):
        before = re.split(r"[,;:]", sentence[: match.start()])[-1]

        if excuse.search(before + " " + match.group(0)) is None:
            return True

    return False


def grade(text: str, scenario_id: str) -> list[str]:
    errors: list[str] = []

    for sentence in _sentences(_plain(text)):
        if scenario_id in RAN_BEFORE:
            # "never started" cannot excuse itself: only words BEFORE it do.
            for match in _NOT_STARTED.finditer(sentence):
                before = re.split(r"[,;:]", sentence[: match.start()])[-1]
                idiom = scenario_id not in RUNNING_NOW and re.match(
                    r"\s*(?:fail\w*|unable)", match.group(0), _I
                )

                if not idiom and _DENIAL.search(before) is None:
                    errors.append("never_started_but_ran")

        if (
            re.search(rf"\b{_OOM}\b", sentence, _I)
            and re.search(r"\b(?:memory|resource)\s+requests?\b", sentence, _I)
            and re.search(
                r"\b(?:due\s+to|because|caus\w+|result\w*|lead\w*|insufficient|too\s+(?:low|small)|trigger\w*)\b",
                sentence, _I,
            )
            and not re.search(r"\blimits?\b|\bpressure\b|\bevict\w*|\bqos\b", sentence, _I)
            and not _DENIAL.search(sentence)
        ):
            errors.append("request_blamed_for_oom")

        if any(
            p.search(sentence) and not _DENIAL.search(sentence) for p in _REQUEST_ROLE
        ):
            errors.append("request_limit_role_confusion")

        if _asserts(_PROVES, sentence, excuse=_DENIAL):
            errors.append("restart_count_proves_cause")

        if (
            scenario_id in READY_NOW
            and not _PAST.search(sentence)
            and any(
                _DENIAL.search(re.split(r"[,;:]", sentence[: m.start()])[-1]) is None
                for m in _NOT_READY.finditer(sentence)
            )
        ):
            errors.append("not_ready_but_ready")

        if scenario_id in READY_NOW and _asserts(_SHOWS_FAILURE_NOW, sentence, excuse=_DENIAL):
            errors.append("restart_count_shows_failure_now")

    return sorted(set(errors))
