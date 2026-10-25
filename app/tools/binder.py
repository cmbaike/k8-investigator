from pydantic import ValidationError
from app.tools.investigation import InvestigationContext

from app.tools.arguments import TOOL_ARGUMENT_MODELS
from app.tools.identifiers import (
    extract_user_identifiers,
    find_asserted_user_identifier,
)
from app.tools.intent import validate_proposed_tool_intent
from app.tools.models import ToolCall
from app.tools.operation_authority import (
    OperationAuthorityMode,
    authorize_proposed_operation,
)
from app.tools.provenance import (
    ArgumentProvenanceError,
    ArgumentSource,
    AssertionStatus,
    GroundedArgument,
    GroundedToolCall,
    validate_authorized_scope_argument,
    validate_tool_observation_argument,
    validate_user_argument,
)
from app.tools.registry import get_tool

from app.tools.operation_authority import (
    OperationAuthorityMode,
    authorize_proposed_operation,
)
from app.tools.scope_policy import (
    validate_investigation_scope,
)


class ToolBindingError(ValueError):
    pass

class UngroundedOptionalCandidateError(ToolBindingError):
    pass

class CandidateNotGroundedError(ToolBindingError):
    pass


OPERATIONAL_IDENTIFIER_ARGUMENTS = {
    "namespace",
    "pod",
    "deployment",
    "container",
}

OBSERVATION_FIELDS_BY_ARGUMENT = {
    "pod": {
        "pods[].name",
    },
    # Container names observed in a describe_pod result. Without this a
    # multi-container pod's `container` argument was silently dropped.
    "container": {
        "containers[].name",
    },
}


def _can_omit_ungrounded_candidate(
    schema: type,
    name: str,
    error: ToolBindingError,
) -> bool:
    field = schema.model_fields.get(name)

    if field is None or field.is_required():
        return False

    message = str(error)

    return (
        "is not grounded in the user input" in message
        or "is not asserted in the user input" in message
    )


def _bind_grounded_tool_call(
    grounded_call: GroundedToolCall,
    user_text: str,
    context: InvestigationContext | None = None,
) -> ToolCall:
    definition = get_tool(grounded_call.name)

    if definition is None:
        raise ToolBindingError(
            f"Unknown tool: {grounded_call.name!r}."
        )

    schema = TOOL_ARGUMENT_MODELS.get(grounded_call.name)

    if schema is None:
        raise ToolBindingError(
            f"No argument schema registered for tool: "
            f"{grounded_call.name!r}."
        )

    arguments: dict[str, str | int] = {}

    for argument in grounded_call.arguments:
        if argument.name in arguments:
            raise ToolBindingError(
                f"Duplicate argument: {argument.name!r}."
            )
            
        if argument.assertion != AssertionStatus.ASSERTED:
            raise ToolBindingError(
                f"Argument {argument.name!r} is not asserted."
            )            
            
        try:
           if argument.source == ArgumentSource.USER:
              validate_user_argument(
                 argument,
                 user_text,
            )

           elif argument.source == ArgumentSource.TOOL_OBSERVATION:
              validate_tool_observation_argument(
                 argument,
            )

           elif argument.source == ArgumentSource.AUTHORIZED_SCOPE:
              # Only a context whose scope the application bound can supply
              # this source, and only for the namespace it authorized.
              if context is None or context.investigation_kind is None:
                  raise ToolBindingError(
                      "Authorized-scope arguments require a bound "
                      "investigation context."
                  )

              validate_authorized_scope_argument(
                 argument,
                 context.authorized_namespace,
            )

           else:
              raise ToolBindingError(
                  f"Unsupported argument source: "
                  f"{argument.source!r}."
          )

        except ArgumentProvenanceError as exc:
           raise ToolBindingError(str(exc)) from exc    

        arguments[argument.name] = argument.value

    try:
        validated = schema.model_validate(arguments)
    except ValidationError as exc:
        raise ToolBindingError(
            f"Invalid arguments for tool "
            f"{grounded_call.name!r}."
        ) from exc

    return ToolCall(
        name=grounded_call.name,
        arguments=validated.model_dump(),
    )


def ground_user_candidate(
    name: str,
    value: str | int,
    user_text: str,
) -> GroundedArgument:
    value_text = str(value).strip()

    if not value_text:
        raise ToolBindingError(
            f"Candidate argument {name!r} has an empty value."
        )

    if name in OPERATIONAL_IDENTIFIER_ARGUMENTS:
        identifiers = extract_user_identifiers(user_text)

        identifier = find_asserted_user_identifier(
            identifiers,
            name,
            value_text,
        )

        if identifier is None:
            raise CandidateNotGroundedError(
                f"Candidate operational identifier {name!r} "
                "is not asserted in the user input."
            )

        return GroundedArgument(
            name=name,
            value=value,
            source=identifier.source,
            evidence=identifier.evidence,
            assertion=identifier.assertion,
        )

    if value_text not in user_text:
        raise CandidateNotGroundedError(
            f"Candidate argument {name!r} is not grounded "
            "in the user input."
        )

    return GroundedArgument(
        name=name,
        value=value,
        source=ArgumentSource.USER,
        evidence=value_text,
        assertion=AssertionStatus.ASSERTED,
    )


def bind_proposed_user_tool_call(
    proposed_call: ToolCall,
    user_text: str,
    *,
    context: InvestigationContext | None = None,
) -> ToolCall:
    validate_proposed_tool_intent(
        proposed_call,
        user_text,
    )

    authority=authorize_proposed_operation(
        proposed_call,
        user_text,
        bound_kind=(
            context.investigation_kind if context is not None else None
        ),
    )
    
    if authority.mode == OperationAuthorityMode.INVESTIGATION:
       if context is None:
         raise ToolBindingError(
            "Investigation operation requires an "
            "authorized investigation context."
         )
         
       if context.user_text != user_text:
          raise ToolBindingError(
            "Investigation context does not match the user request."
        )  
         
       validate_investigation_scope(
        proposed_call,
        context,
     )

    schema = TOOL_ARGUMENT_MODELS.get(proposed_call.name)

    if schema is None:
        raise ToolBindingError(
            f"No argument schema registered for tool: "
            f"{proposed_call.name!r}."
        )

    grounded_arguments: list[GroundedArgument] = []

    for name, value in proposed_call.arguments.items():
        if name not in schema.model_fields:
            raise ToolBindingError(
                f"Unknown argument {name!r} for tool "
                f"{proposed_call.name!r}."
            )

        scoped = _ground_authorized_scope(name, value, context)

        if scoped is not None:
            grounded_arguments.append(scoped)
            continue

        try:
            grounded = ground_user_candidate(
                name,
                value,
                user_text,
            )
        except CandidateNotGroundedError as user_error:
            grounded = None
            if (
                 context is not None
                 and name in OPERATIONAL_IDENTIFIER_ARGUMENTS
               ):
                 try: 
                     grounded = ground_observed_candidate(
                         name,
                         value,
                         context,
                     )
                 except CandidateNotGroundedError:
                     pass
            
            
            if grounded is None:
                if _field_has_application_default(
                    schema,
                    name,
                ):
                    continue

                raise user_error

        grounded_arguments.append(grounded)

    grounded_call = GroundedToolCall(
        name=proposed_call.name,
        arguments=grounded_arguments,
    )

    return _bind_grounded_tool_call(
        grounded_call,
        user_text,
        context,
    )


def _ground_authorized_scope(
    name: str,
    value: str | int,
    context: InvestigationContext | None,
) -> GroundedArgument | None:
    """Ground `namespace` from the application-bound scope.

    A question need not state the namespace: the authenticated request did.
    Only an exact match with the bound namespace is grounded here; any other
    value falls through to the existing user-text grounding, where it can only
    succeed if the text asserts it, and is then rejected by the scope check.
    """
    if (
        name != "namespace"
        or context is None
        or context.investigation_kind is None
        or not context.authorized_namespace
        or str(value) != context.authorized_namespace
    ):
        return None

    return GroundedArgument(
        name=name,
        value=value,
        source=ArgumentSource.AUTHORIZED_SCOPE,
        evidence=f"authorized-scope:{context.authorized_namespace}",
        assertion=AssertionStatus.ASSERTED,
    )

    
def ground_observed_candidate(
    name: str,
    value: str | int,
    context: InvestigationContext,
) -> GroundedArgument:
    value_text = str(value).strip()

    if not value_text:
        raise CandidateNotGroundedError(
            f"Candidate argument {name!r} has an empty value."
        )

    allowed_fields = OBSERVATION_FIELDS_BY_ARGUMENT.get(name)

    if not allowed_fields:
        raise CandidateNotGroundedError(
            f"Candidate argument {name!r} cannot be grounded "
            "from tool observations."
        )

    for field in allowed_fields:
        matches = context.find_observations(
            field=field,
            value=value,
        )

        if not matches:
            continue

        observation = matches[0]

        return GroundedArgument(
            name=name,
            value=value,
            source=ArgumentSource.TOOL_OBSERVATION,
            evidence=(
                f"{observation.tool}:"
                f"{observation.field}:"
                f"{observation.request_id}"
            ),
            assertion=AssertionStatus.ASSERTED,
        )

    raise CandidateNotGroundedError(
        f"Candidate operational identifier {name!r} "
        "is not present in trusted tool observations."
    )    
    
    
def _field_has_application_default(
    schema: type,
    name: str,
) -> bool:
    field = schema.model_fields.get(name)

    if field is None:
        return False

    return not field.is_required()


def bind_user_tool_call(
    grounded_call: GroundedToolCall,
    user_text: str,
) -> ToolCall:
    """
    Backward-compatible v0.7 entry point.

    This path accepts user-sourced provenance only.
    """

    for argument in grounded_call.arguments:
        if argument.source != ArgumentSource.USER:
            raise ToolBindingError(
                f"Argument {argument.name!r} is not user-sourced."
            )

    return _bind_grounded_tool_call(
        grounded_call,
        user_text,
    )
     