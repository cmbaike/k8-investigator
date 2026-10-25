import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_POD_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$")


class StrictArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NamespaceArguments(StrictArguments):
    namespace: str = Field(min_length=1, max_length=253)


class PodArguments(NamespaceArguments):
    pod: str = Field(min_length=1, max_length=253)


class EventsArguments(NamespaceArguments):
    """Events for the namespace, optionally bound to one pod.

    The pod is passed to the API server as a field selector, so a pod-bound
    call returns (and the application keeps) only that pod's events. The name
    must be a valid Kubernetes pod name: nothing selector-shaped is accepted.
    """

    pod: str | None = Field(default=None, min_length=1, max_length=253)

    @field_validator("pod")
    @classmethod
    def _valid_pod_name(cls, value: str | None) -> str | None:
        if value is not None and not _POD_NAME.fullmatch(value):
            raise ValueError("Invalid pod name.")

        return value


class DeploymentArguments(NamespaceArguments):
    deployment: str = Field(min_length=1, max_length=253)


class LogsArguments(PodArguments):
    container: str | None = Field(default=None, min_length=1, max_length=253)
    tail: int = Field(default=200, ge=1, le=1000)


TOOL_ARGUMENT_MODELS = {
    "k8s.get_pods": NamespaceArguments,
    "k8s.describe_pod": PodArguments,
    "k8s.get_events": EventsArguments,
    "k8s.get_deployment": DeploymentArguments,
    "k8s.describe_workload_config": PodArguments,
    "k8s.get_logs": LogsArguments,
    "k8s.get_previous_logs": LogsArguments,
}


def validate_tool_arguments(name: str, arguments: dict):
    model = TOOL_ARGUMENT_MODELS.get(name)

    if model is None:
        return None

    return model.model_validate(arguments)
