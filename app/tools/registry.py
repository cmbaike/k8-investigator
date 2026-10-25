from app.tools.models import ToolDefinition, ToolRisk


TOOLS: dict[str, ToolDefinition] = {
    "k8s.get_pods": ToolDefinition(
        name="k8s.get_pods",
        description="List Kubernetes pods.",
        risk=ToolRisk.READ_ONLY,
    ),
    "k8s.describe_pod": ToolDefinition(
        name="k8s.describe_pod",
        description="Inspect a Kubernetes pod.",
        risk=ToolRisk.READ_ONLY,
    ),
    "k8s.get_events": ToolDefinition(
        name="k8s.get_events",
        description="Read Kubernetes events.",
        risk=ToolRisk.READ_ONLY,
    ),
    "k8s.get_deployment": ToolDefinition(
        name="k8s.get_deployment",
        description="Inspect a Kubernetes deployment.",
        risk=ToolRisk.READ_ONLY,
    ),
    "k8s.describe_workload_config": ToolDefinition(
        name="k8s.describe_workload_config",
        description=(
            "Summarize a pod's owning Deployment configuration "
            "(env variable names and source types only; no values or commands)."
        ),
        risk=ToolRisk.READ_ONLY,
    ),
    "k8s.get_logs": ToolDefinition(
        name="k8s.get_logs",
        description="Read container logs.",
        risk=ToolRisk.READ_ONLY,
    ),
    "k8s.get_previous_logs": ToolDefinition(
        name="k8s.get_previous_logs",
        description="Read logs from the previous container instance.",
        risk=ToolRisk.READ_ONLY,
    ),

    # Registered for policy testing only. There is deliberately no
    # executor for these state-changing operations in v0.7.
    "k8s.restart_deployment": ToolDefinition(
        name="k8s.restart_deployment",
        description="Restart a Kubernetes deployment.",
        risk=ToolRisk.STATE_CHANGING,
    ),
    "k8s.delete_pod": ToolDefinition(
        name="k8s.delete_pod",
        description="Delete a Kubernetes pod.",
        risk=ToolRisk.DESTRUCTIVE,
    ),
}


def get_tool(name: str) -> ToolDefinition | None:
    return TOOLS.get(name)
