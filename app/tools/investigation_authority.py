import re
from dataclasses import dataclass
from enum import StrEnum

from app.tools.models import ToolCall


class InvestigationAuthorityError(ValueError):
    pass


class InvestigationKind(StrEnum):
    K8S_WORKLOAD = "k8s_workload"


@dataclass(frozen=True)
class InvestigationAuthority:
    kind: InvestigationKind
    
_INVESTIGATION_TOOLS: dict[
    InvestigationKind,
    frozenset[str],
] = {
    InvestigationKind.K8S_WORKLOAD: frozenset({
        "k8s.get_pods",
        "k8s.describe_pod",
        "k8s.get_logs",
        "k8s.get_previous_logs",
        "k8s.get_events",
        "k8s.get_deployment",
        "k8s.describe_workload_config",
    }),
}    

_INVESTIGATION_VERBS = re.compile(
    r"\b(?:investigate|diagnose|troubleshoot)\b",
    re.IGNORECASE,
)

_WORKLOAD_TARGETS = re.compile(
    r"\b(?:workload|workloads|pod|pods|deployment|deployments|service|services)\b",
    re.IGNORECASE,
)

_UNTRUSTED_INTENT = re.compile(
    r"\b(?:"
    r"do\s+not|don't|dont|never|"
    r"avoid|"
    r"assume|suppose|imagine|pretend|"
    r"hypothetically|"
    r"what\s+if"
    r")\b",
    re.IGNORECASE,
)

def infer_investigation_authority(
    user_text: str,
) -> InvestigationAuthority | None:
    """
    Conservative recognition of a workload investigation request.

    No model classification is used to grant authority.
    """

    if _UNTRUSTED_INTENT.search(user_text):
        return None

    if not _INVESTIGATION_VERBS.search(user_text):
        return None

    if not _WORKLOAD_TARGETS.search(user_text):
        return None

    return InvestigationAuthority(
        kind=InvestigationKind.K8S_WORKLOAD,
    )
    


def allowed_investigation_tools(
    authority: InvestigationAuthority,
) -> frozenset[str]:
    try:
        return _INVESTIGATION_TOOLS[authority.kind]
    except KeyError as exc:
        raise InvestigationAuthorityError(
            f"Unsupported investigation kind: {authority.kind!r}."
        ) from exc    
    

def validate_investigation_operation(
    proposed_call: ToolCall,
    authority: InvestigationAuthority,
) -> None:
    allowed_tools = allowed_investigation_tools(authority)

    if proposed_call.name not in allowed_tools:
        raise InvestigationAuthorityError(
            f"Tool {proposed_call.name!r} is not authorized "
            f"for investigation kind {authority.kind!r}."
        )
