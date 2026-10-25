from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class ArgumentSource(StrEnum):
    USER = "user"
    TOOL_OBSERVATION = "tool_observation"
    # The namespace the application bound to the investigation from the
    # authenticated request. Never produced from model output or question text.
    AUTHORIZED_SCOPE = "authorized_scope"


class GroundedArgument(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    name: str
    value: str | int
    source: ArgumentSource
    evidence: str
    assertion: AssertionStatus


class GroundedToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    arguments: list[GroundedArgument]
    

class ArgumentProvenanceError(ValueError):
    pass


class AssertionStatus(StrEnum):
    ASSERTED = "asserted"
    UNTRUSTED = "untrusted"


def validate_user_argument(
    argument: GroundedArgument,
    user_text: str,
) -> None:
    if argument.source != ArgumentSource.USER:
        raise ArgumentProvenanceError(
            "Argument is not declared as user-sourced."
        )

    if argument.assertion != AssertionStatus.ASSERTED:
        raise ArgumentProvenanceError(
            "Argument is not an asserted operational identifier."
        )

    value = str(argument.value).strip()
    evidence = argument.evidence.strip()

    if not value:
        raise ArgumentProvenanceError(
            "Argument value must not be empty."
        )

    if not evidence:
        raise ArgumentProvenanceError(
            "Argument evidence must not be empty."
        )

    if evidence not in user_text:
        raise ArgumentProvenanceError(
            "Argument evidence is not present in the user input."
        )

    if value not in evidence:
        raise ArgumentProvenanceError(
            "Argument value is not present in its evidence."
        )  
        
def validate_tool_observation_argument(
    argument: GroundedArgument,
) -> None:
    if argument.source != ArgumentSource.TOOL_OBSERVATION:
        raise ArgumentProvenanceError(
            "Argument is not declared as tool-observation-sourced."
        )

    if argument.assertion != AssertionStatus.ASSERTED:
        raise ArgumentProvenanceError(
            "Tool observation is not asserted."
        )

    value = str(argument.value).strip()
    evidence = argument.evidence.strip()

    if not value:
        raise ArgumentProvenanceError(
            "Argument value must not be empty."
        )

    if not evidence:
        raise ArgumentProvenanceError(
            "Tool observation evidence must not be empty."
        )        


def validate_authorized_scope_argument(
    argument: GroundedArgument,
    authorized_namespace: str | None,
) -> None:
    """The only argument this source may supply is the bound namespace."""
    if argument.source != ArgumentSource.AUTHORIZED_SCOPE:
        raise ArgumentProvenanceError(
            "Argument is not declared as authorized-scope-sourced."
        )

    if argument.name != "namespace":
        raise ArgumentProvenanceError(
            "Only the namespace may be sourced from the authorized scope."
        )

    if argument.assertion != AssertionStatus.ASSERTED:
        raise ArgumentProvenanceError(
            "Authorized scope is not asserted."
        )

    if not authorized_namespace:
        raise ArgumentProvenanceError(
            "Investigation has no authorized namespace."
        )

    if str(argument.value) != authorized_namespace:
        raise ArgumentProvenanceError(
            "Namespace differs from the authorized investigation scope."
        )
