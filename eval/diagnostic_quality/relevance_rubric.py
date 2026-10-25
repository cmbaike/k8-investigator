"""Relevance grading for hypotheses: does an explanation address THIS failure?

An additive grader (the frozen v2 rubric and the lifecycle rubric are
untouched). It imports nothing from `app`, so "the application accepted it" and
"it explains the failure" stay separate measurements.

Each scenario has an ESTABLISHED ABNORMALITY (what Kubernetes reported). A
hypothesis is classified from its `possible_explanation` alone:

  relevant    names a mechanism that can explain the abnormality
  irrelevant  names a mechanism for a stage that did NOT fail, one the
              recorded state contradicts, or (for scheduling) a constraint the
              scheduler did not report. Irrelevant wins over relevant: a
              sentence that explains the failure AND blames a stage that did
              not fail is still misleading.
  generic     names no mechanism it can be tied to (or only one that neither
              explains nor contradicts)

This is a MEASUREMENT instrument built from word families, as the other
rubrics are; it is not a rule the application applies, and category agreement
is not evidence of causal relevance. It is validated against a hand review
(`relevance_review.json`; see `review_agreement`).

Statements that DENY a family ("no liveness probe is declared") do not count as
mentioning it for the irrelevant check unless the sentence still blames it
(the denial comes first: "no liveness probe is declared" is a statement, "a
liveness probe failure, though none is declared" is a blame).
"""

import re

_I = re.IGNORECASE


def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, _I)


FAMILIES: dict[str, re.Pattern[str]] = {
    "scheduling": _re(
        r"\b(?:unschedulable|unscheduled|scheduler|scheduling|schedulable|scheduled\s+(?:on|to|onto)\b|node\s+selector|affinity|taints?|"
        r"tolerations?|allocatable|available\s+nodes?|on\s+(?:the\s+)?nodes?)\b"
    ),
    "taint": _re(r"\btaints?\b|\btoleration"),
    "placement": _re(r"\bnode\s+selector|\baffinity\b|\bnode\s+labels?\b|\blabels?\b"),
    "volume_claim": _re(r"\bpersistentvolumeclaim\b|\bpvc\b|\bvolume\s+claim\b|\bstorage\s*class\b"),
    "cpu_memory_capacity": _re(
        r"\b(?:insufficient|enough|sufficient)\s+(?:\w+\s+){0,2}(?:cpu|memory|resources?)\b"
        r"|\bresource\s+(?:requests?|requirements?)\b|\bcapacity\b"
        r"|\bcpu\b"
    ),
    "image_pull": _re(
        r"\b(?:image|registry|tag|pull\w*|credentials?|authenticat\w+|"
        r"imagepullsecrets?|repository)\b"
    ),
    "volume_mount": _re(
        r"\b(?:volume\w*|mount\w*|configmaps?|config_map|secrets?|"
        r"persistentvolumeclaims?)\b"
    ),
    "readiness_probe": _re(r"\breadiness\b|\bnot\s+ready\b"),
    "liveness_probe": _re(r"\bliveness\b"),
    "probe_any": _re(r"\bprobes?\b|\bhealth[\s-]?checks?\b"),
    "oom": _re(r"\boom\w*|\bout[\s-]of[\s-]memory\b|\bmemory\b"),
    "oom_strict": _re(r"\boom\w*|\bout[\s-]of[\s-]memory\b|\bmemory\s+(?:leak|exhaust\w+|pressure)\b"),
    "startup_command": _re(
        r"\b(?:entrypoint|entry\s+point|startup\s+(?:command|process|script)|"
        r"start-?up\s+(?:command|process|script)|container\s+command)\b"
    ),
    "image_compat": _re(
        r"\bimage\b[^.]{0,40}\b(?:suitab\w+|compatib\w+|incompatib\w+|corrupt\w*)\b"
        r"|\b(?:incompatible|unsuitable|corrupt\w*)\s+(?:container\s+)?image\b"
    ),
    "crash": _re(
        r"\bcrash\w*|\bunhandled\s+exception|\bexception\b|\bexit\s+codes?\b|\bnon-?zero\b|"
        r"\bstartup\b|\bstart\s+(?:up|properly)|\bconfiguration\b|\benvironment\b|"
        r"\bdependenc\w+|\bapplication(?:'s)?\s+(?:code|logic|error|bug)"
    ),
    "normal_exit": _re(
        r"\bexited\s+(?:normally|cleanly|by\s+itself)\b|\bnormal(?:ly)?\s+(?:exit|termination)\b|"
        r"\bcompleted\b|\bexit\s+code\s+0\b|\brestart\s+policy\b|\bfinished\b|\bprocess\s+completion\b|"
        r"\bgraceful\w*|\bsigterm\b|\bsignal\b|\bexternal\s+(?:trigger|event|signal)\b|"
        r"\bscheduled\s+(?:event|process|maintenance|restart)\b|\bsystem\s+(?:event|signal)\b"
    ),
    "probe_mechanics": _re(
        r"\b(?:path|port|endpoint|timeout|timing|initial\s+delay|period|failure\s+threshold|"
        r"initiali[sz]\w+|dependenc\w+|not\s+responding|responding|status\s+codes?|slow)\b"
    ),
    "restart_cause": _re(r"\brestart\w*|\bkill\w*|\bterminat\w*"),
    "resource_exhaustion": _re(
        r"\bresource\s+(?:exhaustion|constraints?|limits?|pressure)\b|"
        r"\binsufficient\s+(?:\w+\s+)?(?:memory|resources?|cpu)\b|"
        r"\b(?:memory|cpu)\s+(?:or\s+(?:memory|cpu)\s+)?limits?\b"
    ),
}

_DENIAL = _re(r"\b(?:no|not|never|neither|nor|without|none|cannot)\b|n't")


def _blamed(family: str, text: str) -> bool:
    """The family is mentioned and not merely denied before the mention."""
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        for match in FAMILIES[family].finditer(sentence):
            before = re.split(r"[,;:]", sentence[: match.start()])[-1]
            window = re.sub(r"\b(?:may|might|could)\s+not\b", " ", before, flags=_I)

            if _DENIAL.search(window) is None:
                return True

    return False


# Per scenario: families that explain the abnormality, and families that are
# off-stage (a stage that did not fail, or a mechanism the recorded state
# excludes).
_NEVER_RAN = ("readiness_probe", "liveness_probe", "probe_any", "oom_strict", "crash", "image_pull")


def _spec(explains, off, soft=()):
    """`soft` families are off-stage only when no `explains` family is also
    present: "a memory-hungry startup process" explains an OOM kill, "a
    misconfigured startup command" does not."""
    return {"explains": tuple(explains), "off_stage": tuple(off), "soft": tuple(soft)}


SPECS: dict[str, dict[str, tuple[str, ...]]] = {
    "sched_cpu": _spec(
        ["cpu_memory_capacity"],
        ["taint", "placement", "volume_claim", "image_pull", "readiness_probe",
         "liveness_probe", "probe_any", "oom_strict"],
    ),
    "sched_memory": _spec(
        ["cpu_memory_capacity"],
        ["taint", "placement", "volume_claim", "image_pull", "readiness_probe",
         "liveness_probe", "probe_any", "oom_strict"],
    ),
    "sched_taint": _spec(
        ["taint"],
        ["cpu_memory_capacity", "placement", "volume_claim", "image_pull",
         "readiness_probe", "liveness_probe", "probe_any", "oom_strict"],
    ),
    "sched_selector": _spec(
        ["placement"],
        ["cpu_memory_capacity", "taint", "volume_claim", "image_pull",
         "readiness_probe", "liveness_probe", "probe_any", "oom_strict"],
    ),
    "sched_missing_pvc": _spec(
        ["volume_claim"],
        ["cpu_memory_capacity", "taint", "placement", "image_pull",
         "readiness_probe", "liveness_probe", "probe_any", "oom_strict"],
    ),
    # Several constraints reported together: all three are on topic; the
    # unreported ones (selector, volume claim) are off.
    "sched_multiple": _spec(
        ["cpu_memory_capacity", "taint"],
        ["placement", "volume_claim", "image_pull", "readiness_probe",
         "liveness_probe", "probe_any", "oom_strict"],
    ),
    "image_pull": _spec(
        ["image_pull"],
        ["scheduling", "volume_mount", "readiness_probe", "liveness_probe",
         "probe_any", "oom_strict", "startup_command"],
    ),
    "mount_failure": _spec(
        ["volume_mount"],
        ["scheduling", "image_pull", "readiness_probe", "liveness_probe",
         "probe_any", "oom_strict"],
    ),
    "oom_killed": _spec(
        ["oom"],
        ["scheduling", "image_pull", "readiness_probe", "liveness_probe", "probe_any"],
        soft=["startup_command", "image_compat"],
    ),
    "oom_recovered": _spec(
        ["oom"],
        ["scheduling", "image_pull", "readiness_probe", "liveness_probe", "probe_any"],
        soft=["startup_command", "image_compat"],
    ),
    "running_not_ready": _spec(
        ["readiness_probe", "probe_mechanics"],
        ["scheduling", "image_pull", "liveness_probe", "oom_strict", "volume_mount"],
    ),
    "liveness_failure": _spec(
        ["liveness_probe", "probe_mechanics"],
        ["scheduling", "image_pull", "readiness_probe", "oom_strict", "volume_mount",
         "resource_exhaustion"],
    ),
    "crash_loop": _spec(
        ["crash", "startup_command"],
        ["scheduling", "image_pull", "readiness_probe", "liveness_probe",
         "probe_any", "oom_strict", "image_compat"],
    ),
    "restart_history": _spec(
        ["normal_exit"],
        ["scheduling", "image_pull", "readiness_probe", "liveness_probe",
         "probe_any", "oom_strict", "volume_mount", "resource_exhaustion"],
    ),
    "healthy": _spec([], list(FAMILIES)),
}

# "unit" families in sched_*: capacity words inside other statements are
# harmless ("requests" are normal), so for scheduling the capacity family is
# only off-stage when the scheduler did not report it.
RELEVANT = "relevant"
GENERIC = "generic"
IRRELEVANT = "irrelevant"


def classify(scenario_id: str, text: str) -> dict:
    """{'label': relevant|generic|irrelevant, 'off_stage': [...], 'explains': [...]}"""
    spec = SPECS[scenario_id]
    hits = [f for f in spec["explains"] if _blamed(f, text)]
    off = [f for f in spec["off_stage"] if _blamed(f, text)]
    off += [f for f in spec["soft"] if not hits and _blamed(f, text)]

    # "scheduling" words (nodes, scheduled) also appear in sched_* scenarios'
    # correct explanations; off-stage lists for those scenarios name only the
    # constraints that were NOT reported.
    if off:
        label = IRRELEVANT
    elif hits:
        label = RELEVANT
    else:
        label = GENERIC

    return {"label": label, "off_stage": off, "explains": hits}


def review_agreement(review: list[dict]) -> dict:
    """Agreement between this grader and a hand review.
    `review` entries: {scenario, text, label}."""
    agree = 0
    disagreements = []

    for entry in review:
        graded = classify(entry["scenario"], entry["text"])["label"]

        if graded == entry["label"]:
            agree += 1
        else:
            disagreements.append({**entry, "graded": graded})

    return {
        "reviewed": len(review),
        "agree": agree,
        "rate": round(agree / len(review), 3) if review else None,
        "disagreements": disagreements,
    }
