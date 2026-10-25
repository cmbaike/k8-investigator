"""Safe workload-configuration inspection (k8s.describe_workload_config).

No cluster or model is contacted. Kubernetes objects are real
`kubernetes.client` models; the API clients are mocks.

Security properties exercised:
  * env VALUES, command text, argument text and annotations never leave the
    handler (sentinels are planted in each and searched for everywhere);
  * ownership is proven by owner references + UIDs, not names;
  * startup behaviour is a fixed-vocabulary static analysis, never a hash or
    truncation of the command;
  * observations and report findings carry only validated vocabulary.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from kubernetes import client
from kubernetes.client.exceptions import ApiException

from app.reports.config_grounding import (
    build_configuration_findings,
    build_configuration_uncertainties,
)
from app.reports.grounding import (
    MAX_UNCERTAINTIES,
    bound_uncertainties,
    build_grounded_report,
)
from app.reports.snapshot import build_investigation_evidence_snapshot
from app.reports.validation import validate_report_snapshot
from app.tools import handlers
from app.tools.arguments import PodArguments, validate_tool_arguments
from app.tools.handlers import KubernetesToolError, describe_workload_config
from app.tools.investigation import InvestigationContext
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus
from app.tools.observations import observations_from_execution
from app.tools.orchestrator import READ_ONLY_INVESTIGATION_TOOLS
from app.tools.registry import TOOLS
from app.tools.workload_config import (
    WORKLOAD_CONFIG_TOOL,
    WorkloadConfigError,
    analyze_startup,
    build_workload_config,
    summarize_environment,
)

NS = "ai-ops-demo"
POD = "billing-7c9d5-abcde"
RS = "billing-7c9d5"
DEP = "billing"
ENV_SECRET = "ENVVALUE-SENTINEL-93f1"
CMD_SECRET = "CMD-SENTINEL-77a2"
ARG_SECRET = "ARG-SENTINEL-55c8"
ANNOTATION_SECRET = "ANNOTATION-SENTINEL-12d4"
SENTINELS = (ENV_SECRET, CMD_SECRET, ARG_SECRET, ANNOTATION_SECRET)

DEMO_SCRIPT = f"echo 'starting {CMD_SECRET}'; exit 1"


# ---------------------------------------------------------------- builders


def owner(kind, name, uid):
    return client.V1OwnerReference(
        api_version="apps/v1", kind=kind, name=name, uid=uid, controller=True
    )


def container(name="app", **overrides):
    values = {
        "name": name,
        "image": "registry.example.com/team/app:1.4.2",
        "env": [
            client.V1EnvVar(name="PLAIN_SETTING", value=ENV_SECRET),
            client.V1EnvVar(
                name="DB_PASSWORD",
                value_from=client.V1EnvVarSource(
                    secret_key_ref=client.V1SecretKeySelector(
                        name="db-secret", key="password"
                    )
                ),
            ),
            client.V1EnvVar(
                name="FEATURE_FLAGS",
                value_from=client.V1EnvVarSource(
                    config_map_key_ref=client.V1ConfigMapKeySelector(
                        name="flags", key="flags"
                    )
                ),
            ),
            client.V1EnvVar(
                name="POD_IP",
                value_from=client.V1EnvVarSource(
                    field_ref=client.V1ObjectFieldSelector(field_path="status.podIP")
                ),
            ),
        ],
        "command": ["/bin/sh", "-c", DEMO_SCRIPT],
        "args": [ARG_SECRET],
    }
    values.update(overrides)
    return client.V1Container(**values)


def make_pod(containers=None, *, owners=None, labels=None, namespace=NS, name=POD):
    return client.V1Pod(
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=namespace,
            uid="pod-uid",
            labels={"app": "billing"} if labels is None else labels,
            annotations={
                "kubectl.kubernetes.io/last-applied-configuration": ANNOTATION_SECRET
            },
            owner_references=(
                [owner("ReplicaSet", RS, "rs-uid")] if owners is None else owners
            ),
        ),
        spec=client.V1PodSpec(containers=containers or [container()]),
    )


def make_rs(*, owners=None, namespace=NS, name=RS, uid="rs-uid"):
    return client.V1ReplicaSet(
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=namespace,
            uid=uid,
            owner_references=(
                [owner("Deployment", DEP, "dep-uid")] if owners is None else owners
            ),
        ),
    )


def make_dep(*, namespace=NS, name=DEP, uid="dep-uid", match_labels=None):
    return client.V1Deployment(
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=namespace,
            uid=uid,
            annotations={"note": ANNOTATION_SECRET},
        ),
        spec=client.V1DeploymentSpec(
            replicas=2,
            selector=client.V1LabelSelector(
                match_labels={"app": "billing"} if match_labels is None else match_labels
            ),
            template=client.V1PodTemplateSpec(),
        ),
        status=client.V1DeploymentStatus(
            ready_replicas=None, available_replicas=None, updated_replicas=2
        ),
    )


def build(**kwargs):
    return build_workload_config(
        namespace=NS,
        pod=kwargs.get("pod") or make_pod(),
        replicaset=kwargs.get("replicaset") or make_rs(),
        deployment=kwargs.get("deployment") or make_dep(),
    )


def assert_no_sentinels(value):
    dumped = json.dumps(value, default=str) if not isinstance(value, str) else value

    for sentinel in SENTINELS:
        assert sentinel not in dumped, sentinel


# ------------------------------------------------- static startup analysis


@pytest.mark.parametrize(
    "command, args, code",
    [
        (["/bin/sh", "-c", "exit 1"], None, 1),
        (["sh", "-c", "exit 0"], None, 0),
        (["bash", "-c", "exit 255"], None, 255),
        (["/bin/sh", "-c", "echo 'missing x'; exit 1"], None, 1),
        (["/bin/sh", "-c", 'echo "a b"; printf done; exit 2'], None, 2),
        (["/bin/sh", "-c", "echo one\necho two\nexit 3"], None, 3),
        (["sh", "-c", "true; : ; exit 4"], None, 4),
        # Command and args split across fields: argv = command + args.
        (["/bin/sh", "-c"], ["echo hi; exit 9"], 9),
        (["/bin/sh"], ["-c", "exit 6"], 6),
        # Anything after an unconditional exit is unreachable.
        (["sh", "-c", "exit 7; echo never"], None, 7),
        # Extra positional arguments ($0, $1) are irrelevant without expansion.
        (["sh", "-c", "exit 5", "name", "extra"], None, 5),
        (["/bin/dash", "-c", "exit 8"], None, 8),
    ],
)
def test_unconditional_exit_is_established(command, args, code):
    result = analyze_startup(command, args)

    assert result["static_analysis"] == "unconditional_exit"
    assert result["static_exit_code"] == code
    assert result["entrypoint_kind"] == "shell_script"


@pytest.mark.parametrize(
    "script",
    [
        # Environment-dependent: must never be called unconditional.
        'exit "$CODE"',
        "exit $?",
        "exit ${CODE:-1}",
        'echo "$X"; exit 1',
        'echo "${X:?missing}"; exit 1',
        "echo `id`; exit 1",
        'echo "$(id)"; exit 1',
        # Control flow / conditional behaviour.
        '[ -z "$X" ] && exit 1',
        "test -z $X || exit 1; exit 0",
        "if [ -z $X ]; then exit 1; fi",
        "while true; do exit 1; done",
        "case $X in a) exit 1;; esac",
        "echo hi && exit 1",
        "echo hi || exit 1",
        "echo hi | cat; exit 1",
        "echo hi > /tmp/x; exit 1",
        "cat < /etc/passwd; exit 1",
        "echo hi &\nexit 1",
        "f() { exit 1; }; f",
        "(exit 1)",
        "{ exit 1; }",
        # Non-inert commands before the exit.
        "sleep 5; exit 1",
        "set -e; exit 1",
        "export A=b; exit 1",
        "A=b; exit 1",
        "./start.sh; exit 1",
        "exec ./app",
        "python app.py",
        "myapp --flag; exit 1",
        # Malformed or unsupported exit forms.
        "exit",
        "exit 1 2",
        "exit 256",
        "exit -1",
        "exit 1a",
        "exit 0x1",
        "echo hi",
        "",
        "   ",
        "# comment\nexit 1",
        "echo 'unterminated; exit 1",
        'echo "unterminated; exit 1',
        'echo "a\\"b"; exit 1',
        "echo hi\\\nexit 1",
        "x" * 5000,
    ],
)
def test_anything_not_provably_unconditional_is_not_established(script):
    result = analyze_startup(["/bin/sh", "-c", script], None)

    assert result["static_analysis"] == "not_established"
    assert result["static_exit_code"] is None


@pytest.mark.parametrize(
    "command, args, kind",
    [
        (None, None, "image_default"),
        ([], [], "image_default"),
        (None, ["--flag"], "image_default"),
        (["/usr/bin/myapp"], ["--serve"], "executable"),
        (["python", "app.py"], None, "executable"),
        (["/bin/sh", "script.sh"], None, "executable"),
        (["/bin/sh", "-c"], None, "executable"),
    ],
)
def test_non_shell_script_startup_is_never_analyzed(command, args, kind):
    result = analyze_startup(command, args)

    assert result["entrypoint_kind"] == kind
    assert result["static_analysis"] == "not_established"
    assert result["static_exit_code"] is None


def test_startup_result_has_only_fixed_vocabulary_and_never_command_text():
    result = analyze_startup(
        ["/bin/sh", "-c", DEMO_SCRIPT], [ARG_SECRET, f"--token={CMD_SECRET}"]
    )

    assert set(result) == {
        "command_declared",
        "args_declared",
        "entrypoint_kind",
        "static_analysis",
        "static_exit_code",
    }
    assert result["command_declared"] is True and result["args_declared"] is True
    assert_no_sentinels(result)
    assert "/bin/sh" not in json.dumps(result)


def test_startup_analysis_is_not_a_hash_or_truncation_of_the_command():
    a = analyze_startup(["sh", "-c", "echo aaaa; exit 1"], None)
    b = analyze_startup(["sh", "-c", "echo bbbb; exit 1"], None)

    # Different commands, same structured facts: nothing derived from the text.
    assert a == b


def test_non_string_command_entries_are_ignored():
    assert analyze_startup([1, None], [{"a": 1}])["entrypoint_kind"] == "image_default"


# --------------------------------------------------------------- environment


def test_environment_exposes_names_and_source_types_only():
    summary = summarize_environment(container())

    assert summary["env"] == [
        {"name": "PLAIN_SETTING", "source": "literal"},
        {"name": "DB_PASSWORD", "source": "secret_reference"},
        {"name": "FEATURE_FLAGS", "source": "config_map_reference"},
        {"name": "POD_IP", "source": "field_reference"},
    ]
    assert summary["env_count"] == 4
    assert summary["env_names_complete"] is True
    assert_no_sentinels(summary)
    # Referenced Secret/ConfigMap names are not exposed either.
    assert "db-secret" not in json.dumps(summary)
    assert "flags" not in json.dumps(summary).replace("FEATURE_FLAGS", "")


def test_empty_literal_value_is_still_a_literal_source():
    summary = summarize_environment(
        container(env=[client.V1EnvVar(name="EMPTY", value="")])
    )

    assert summary["env"] == [{"name": "EMPTY", "source": "literal"}]


def test_env_from_makes_the_name_list_incomplete_without_reading_contents():
    summary = summarize_environment(
        container(
            env=[client.V1EnvVar(name="ONE", value="x")],
            env_from=[
                client.V1EnvFromSource(
                    secret_ref=client.V1SecretEnvSource(name="bulk-secret")
                )
            ],
        )
    )

    assert summary["env_names_complete"] is False
    assert "bulk-secret" not in json.dumps(summary)


def test_environment_names_are_validated_deduplicated_and_bounded():
    env = [client.V1EnvVar(name="GOOD", value="1")]
    env += [client.V1EnvVar(name="GOOD", value="2")]
    env += [client.V1EnvVar(name="bad name", value="3")]
    env += [client.V1EnvVar(name="has]bracket", value="4")]
    env += [client.V1EnvVar(name=f"VAR_{i}", value="v") for i in range(60)]

    summary = summarize_environment(container(env=env))
    names = [item["name"] for item in summary["env"]]

    assert names[0] == "GOOD" and names.count("GOOD") == 1
    assert "bad name" not in names and "has]bracket" not in names
    assert len(names) == 25
    assert summary["env_truncated"] is True
    assert summary["env_count"] == 61


# --------------------------------------------------------- identity / output


def test_summary_is_free_of_values_commands_and_annotations():
    config = build()

    assert_no_sentinels(config)
    assert config["workload"] == {
        "kind": "Deployment",
        "name": DEP,
        "replicaset": RS,
        "ownership_verified": True,
        "desired_replicas": 2,
        "ready_replicas": 0,
        "available_replicas": 0,
        "updated_replicas": 2,
    }
    [app] = config["containers"]
    assert app["name"] == "app"
    assert app["image"] == "registry.example.com/team/app:1.4.2"
    assert app["startup"]["static_exit_code"] == 1


def test_output_keys_are_a_fixed_allowlist():
    config = build()

    assert set(config) == {"namespace", "pod", "workload", "containers"}
    assert set(config["containers"][0]) == {
        "name", "image", "env_count", "env", "env_truncated",
        "env_names_complete", "readiness_probe", "startup",
    }


@pytest.mark.parametrize(
    "image",
    [
        "https://user:pw@registry/app:1",
        "user:hunter2@registry.example.com/app:1",
        "app with space",
        "",
        None,
    ],
)
def test_unsafe_image_strings_are_omitted(image):
    config = build(pod=make_pod([container(image=image)]))

    assert config["containers"][0]["image"] is None


@pytest.mark.parametrize(
    "pod_kwargs",
    [
        {"owners": []},
        {"owners": [owner("StatefulSet", "db", "x")]},
        {"owners": [owner("ReplicaSet", RS, "rs-uid"), owner("ReplicaSet", "b", "u2")]},
        {"owners": [client.V1OwnerReference(
            api_version="apps/v1", kind="ReplicaSet", name=RS, uid="rs-uid", controller=False)]},
    ],
)
def test_pod_must_have_exactly_one_controlling_replicaset(pod_kwargs):
    with pytest.raises(WorkloadConfigError):
        build(pod=make_pod(**pod_kwargs))


@pytest.mark.parametrize(
    "rs_kwargs",
    [
        {"owners": []},
        {"owners": [owner("DaemonSet", "x", "y")]},
        {"uid": "different-uid"},  # same name, different UID: a replaced object
        {"namespace": "other-ns"},
        {"name": "other-rs"},
    ],
)
def test_replicaset_identity_and_ownership_are_verified(rs_kwargs):
    with pytest.raises(WorkloadConfigError):
        build(replicaset=make_rs(**rs_kwargs))


@pytest.mark.parametrize(
    "dep_kwargs",
    [
        {"uid": "different-uid"},
        {"namespace": "other-ns"},
        {"name": "other-deployment"},
        {"match_labels": {"app": "something-else"}},
    ],
)
def test_deployment_identity_and_selector_are_verified(dep_kwargs):
    with pytest.raises(WorkloadConfigError):
        build(deployment=make_dep(**dep_kwargs))


def test_names_are_never_trusted_without_matching_uids():
    # Names line up perfectly; only the UID differs.
    with pytest.raises(WorkloadConfigError):
        build(deployment=make_dep(uid="forged"))


# ------------------------------------------------------------------ handler


def patched_clients(pod=None, rs=None, dep=None):
    core, apps = MagicMock(), MagicMock()
    core.read_namespaced_pod.return_value = pod or make_pod()
    apps.read_namespaced_replica_set.return_value = rs or make_rs()
    apps.read_namespaced_deployment.return_value = dep or make_dep()

    return core, apps


def run_handler(core, apps, namespace=NS, pod=POD):
    with patch.object(handlers, "core_v1", return_value=core), patch.object(
        handlers, "apps_v1", return_value=apps
    ):
        return describe_workload_config(
            PodArguments(namespace=namespace, pod=pod)
        )


def test_handler_reads_only_pod_replicaset_and_deployment_with_timeouts():
    core, apps = patched_clients()

    output = run_handler(core, apps)

    assert [c[0] for c in core.method_calls] == ["read_namespaced_pod"]
    assert [c[0] for c in apps.method_calls] == [
        "read_namespaced_replica_set",
        "read_namespaced_deployment",
    ]
    for mock_call in [*core.method_calls, *apps.method_calls]:
        assert mock_call.kwargs["namespace"] == NS
        assert mock_call.kwargs["_request_timeout"] == handlers.K8S_REQUEST_TIMEOUT
    apps.read_namespaced_replica_set.assert_called_once_with(
        name=RS, namespace=NS, _request_timeout=handlers.K8S_REQUEST_TIMEOUT
    )
    apps.read_namespaced_deployment.assert_called_once_with(
        name=DEP, namespace=NS, _request_timeout=handlers.K8S_REQUEST_TIMEOUT
    )
    assert_no_sentinels(output)
    assert output["workload"]["ownership_verified"] is True


def test_handler_never_touches_secrets_configmaps_or_exec():
    core, apps = patched_clients()

    run_handler(core, apps)

    called = {c[0] for c in [*core.method_calls, *apps.method_calls]}
    assert not any(
        word in name for name in called for word in ("secret", "config_map", "exec", "patch", "delete", "create", "list")
    )


def test_handler_rejects_pod_whose_returned_identity_differs():
    core, apps = patched_clients(pod=make_pod(name="another-pod"))

    with pytest.raises(KubernetesToolError):
        run_handler(core, apps)

    apps.read_namespaced_replica_set.assert_not_called()


def test_handler_rejects_cross_namespace_pod():
    core, apps = patched_clients(pod=make_pod(namespace="other-ns"))

    with pytest.raises(KubernetesToolError):
        run_handler(core, apps)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"rs": make_rs(uid="other")},
        {"dep": make_dep(uid="other")},
        {"dep": make_dep(match_labels={"app": "nope"})},
    ],
)
def test_handler_converts_identity_failures_to_tool_errors(kwargs):
    core, apps = patched_clients(**kwargs)

    with pytest.raises(KubernetesToolError):
        run_handler(core, apps)


def test_handler_reports_a_bare_pod_as_not_deployment_managed():
    core, apps = patched_clients(pod=make_pod(owners=[]))

    with pytest.raises(KubernetesToolError):
        run_handler(core, apps)

    apps.read_namespaced_replica_set.assert_not_called()


@pytest.mark.parametrize("target", ["pod", "rs", "dep"])
def test_handler_surfaces_api_errors_without_response_bodies(target):
    core, apps = patched_clients()
    error = ApiException(status=403, reason="Forbidden")
    error.body = f"secret body {ENV_SECRET}"
    {
        "pod": core.read_namespaced_pod,
        "rs": apps.read_namespaced_replica_set,
        "dep": apps.read_namespaced_deployment,
    }[target].side_effect = error

    with pytest.raises(KubernetesToolError) as caught:
        run_handler(core, apps)

    assert "403" in str(caught.value)
    assert ENV_SECRET not in str(caught.value)


# ----------------------------------------------- registration / authorization


def test_tool_is_registered_read_only_with_strict_arguments():
    assert TOOLS[WORKLOAD_CONFIG_TOOL].risk.value == "read_only"
    assert handlers.HANDLERS[WORKLOAD_CONFIG_TOOL] is describe_workload_config
    assert WORKLOAD_CONFIG_TOOL in READ_ONLY_INVESTIGATION_TOOLS

    validate_tool_arguments(WORKLOAD_CONFIG_TOOL, {"namespace": NS, "pod": POD})

    for bad in (
        {"namespace": NS},
        {"namespace": NS, "pod": POD, "container": "app"},
        {"namespace": NS, "pod": POD, "deployment": DEP},
    ):
        with pytest.raises(Exception):
            validate_tool_arguments(WORKLOAD_CONFIG_TOOL, bad)


def investigation_context(ns=NS, *, with_pod=True, max_steps=10):
    context = InvestigationContext(
        investigation_id="inv-cfg",
        user_text=f"Investigate the failing workload in namespace {ns}.",
        authorized_namespace=ns,
        max_steps=max_steps,
    )

    if with_pod:
        pods = ToolCall(name="k8s.get_pods", arguments={"namespace": ns})
        context.record_execution(
            request_id="r1",
            call=pods,
            result=ToolExecutionResult(
                tool=pods.name,
                status=ToolExecutionStatus.SUCCESS,
                output={"namespace": ns, "pods": [{"name": POD}]},
            ),
        )

    return context


def test_investigation_step_authorizes_and_audits_without_leaking_config():
    from app.tools.orchestrator import execute_investigation_step

    context = investigation_context()
    events = []
    config = build()

    def executor(call):
        return ToolExecutionResult(
            tool=call.name, status=ToolExecutionStatus.SUCCESS, output=config
        )

    call = ToolCall(
        name=WORKLOAD_CONFIG_TOOL, arguments={"namespace": NS, "pod": POD}
    )

    result = execute_investigation_step(
        context=context,
        request_id="r2",
        proposed_call=call,
        audit=events.append,
        executor=executor,
    )

    assert result.status == ToolExecutionStatus.SUCCESS
    assert [e.phase for e in events] == [
        "proposed", "authorized", "execution_started", "completed",
    ]
    assert_no_sentinels(json.dumps([vars(e) for e in events], default=str))
    assert any(o.tool == WORKLOAD_CONFIG_TOOL for o in context.observations)


def test_investigation_step_rejects_other_namespaces_and_ungrounded_pods():
    from app.tools.orchestrator import (
        InvestigationExecutionError,
        execute_investigation_step,
    )

    executed = []

    def executor(call):
        executed.append(call)
        raise AssertionError("must not execute")

    attempts = [
        (investigation_context(), {"namespace": "orders-prod", "pod": POD}),
        (investigation_context(), {"namespace": NS, "pod": "invented-pod"}),
        (investigation_context(with_pod=False), {"namespace": NS, "pod": POD}),
    ]

    for context, arguments in attempts:
        with pytest.raises(Exception) as caught:
            execute_investigation_step(
                context=context,
                request_id="rx",
                proposed_call=ToolCall(name=WORKLOAD_CONFIG_TOOL, arguments=arguments),
                audit=lambda event: None,
                executor=executor,
            )
        assert isinstance(caught.value, (InvestigationExecutionError, ValueError))

    assert executed == []


def test_qwen_proposal_vocabulary_includes_the_tool_with_strict_arguments():
    from app.tools.qwen_proposal import (
        SUPPORTED_INVESTIGATION_TOOLS,
        SYSTEM_PROMPT,
        ProposalFormatError,
        parse_proposal,
    )

    assert WORKLOAD_CONFIG_TOOL in SUPPORTED_INVESTIGATION_TOOLS
    assert WORKLOAD_CONFIG_TOOL in SYSTEM_PROMPT

    step = parse_proposal(
        json.dumps(
            {
                "action": "tool",
                "name": WORKLOAD_CONFIG_TOOL,
                "arguments": {"namespace": NS, "pod": POD},
            }
        )
    )
    assert step is not None

    with pytest.raises(ProposalFormatError):
        parse_proposal(
            json.dumps(
                {
                    "action": "tool",
                    "name": WORKLOAD_CONFIG_TOOL,
                    "arguments": {"namespace": NS},
                }
            )
        )


def test_get_deployment_is_unchanged_and_still_not_an_investigation_tool_for_qwen():
    from app.tools.qwen_proposal import SUPPORTED_INVESTIGATION_TOOLS

    assert "k8s.get_deployment" not in SUPPORTED_INVESTIGATION_TOOLS

    deployment = make_dep()
    apps = MagicMock()
    apps.read_namespaced_deployment.return_value = deployment

    with patch.object(handlers, "apps_v1", return_value=apps):
        output = handlers.get_deployment(
            SimpleNamespace(namespace=NS, deployment=DEP)
        )

    assert set(output) == {
        "name", "namespace", "desired_replicas", "ready_replicas",
        "available_replicas", "updated_replicas", "unavailable_replicas",
    }


# -------------------------------------------------------------- observations


def call_for(namespace=NS, pod=POD):
    return ToolCall(
        name=WORKLOAD_CONFIG_TOOL, arguments={"namespace": namespace, "pod": pod}
    )


def success(output):
    return ToolExecutionResult(
        tool=WORKLOAD_CONFIG_TOOL, status=ToolExecutionStatus.SUCCESS, output=output
    )


def observe(output, *, call=None, result=None):
    return observations_from_execution(
        request_id="r2",
        call=call or call_for(),
        result=result or success(output),
    )


def fields(observations):
    return {o.field: o.value for o in observations}


def test_observations_cover_identity_image_env_and_startup():
    observed = fields(observe(build()))

    assert observed["workload.kind"] == "Deployment"
    assert observed["workload.name"] == DEP
    assert observed["workload.ownership_verified"] is True
    assert observed["workload.replicas.desired"] == 2
    assert observed["containers[app].image"] == "registry.example.com/team/app:1.4.2"
    assert observed["containers[app].env.count"] == 4
    assert observed["containers[app].env.names_complete"] is True
    assert observed["containers[app].env[DB_PASSWORD].source"] == "secret_reference"
    assert observed["containers[app].env[PLAIN_SETTING].source"] == "literal"
    assert observed["containers[app].startup.entrypoint_kind"] == "shell_script"
    assert observed["containers[app].startup.static_analysis"] == "unconditional_exit"
    assert observed["containers[app].startup.static_exit_code"] == 1
    assert_no_sentinels(observed)


def test_every_observation_carries_the_requested_identity():
    for observation in observe(build()):
        assert observation.tool == WORKLOAD_CONFIG_TOOL
        assert (observation.namespace, observation.pod) == (NS, POD)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda o: o.update(namespace="other-ns"),
        lambda o: o.update(pod="other-pod"),
        lambda o: o["workload"].update(ownership_verified=False),
        lambda o: o["workload"].update(ownership_verified="yes"),
        lambda o: o["workload"].update(kind="StatefulSet"),
        lambda o: o.pop("workload"),
        lambda o: o["workload"].update(name=""),
        lambda o: o["workload"].update(name=7),
    ],
)
def test_no_observations_for_mismatched_or_unverified_identity(mutate):
    output = build()
    mutate(output)

    assert observe(output) == []


def test_failed_or_wrong_tool_results_mint_nothing():
    output = build()

    assert observe(output, result=ToolExecutionResult(
        tool=WORKLOAD_CONFIG_TOOL, status=ToolExecutionStatus.ERROR, error="x")) == []
    assert observe(output, result=ToolExecutionResult(
        tool="k8s.describe_pod", status=ToolExecutionStatus.SUCCESS, output=output)) == []
    assert observe("not a dict") == []


def test_smuggled_free_text_is_never_minted():
    output = build()
    app = output["containers"][0]
    app["command"] = ["/bin/sh", "-c", DEMO_SCRIPT]
    app["startup"]["command_text"] = CMD_SECRET
    app["env"].append({"name": "LEAK", "source": "literal", "value": ENV_SECRET})
    app["note"] = ARG_SECRET
    output["annotations"] = {"x": ANNOTATION_SECRET}

    observations = observe(output)

    assert_no_sentinels([o.model_dump() for o in observations])
    assert not any("LEAK].value" in o.field for o in observations)


@pytest.mark.parametrize(
    "item",
    [
        {"name": "bad name", "source": "literal"},
        {"name": "has]bracket", "source": "literal"},
        {"name": "OK", "source": "plaintext-value"},
        {"name": "OK", "source": None},
        {"name": 5, "source": "literal"},
        "OK",
    ],
)
def test_malformed_env_entries_are_ignored(item):
    output = build()
    output["containers"][0]["env"] = [item]

    assert not [o for o in observe(output) if ".env[" in o.field]


@pytest.mark.parametrize(
    "key, value",
    [
        ("image", "not a valid image because of spaces"),
        ("image", "https://u:p@r/x"),
        ("env_count", -1),
        ("env_count", "4"),
        ("env_names_complete", "yes"),
    ],
)
def test_invalid_scalar_values_are_not_minted(key, value):
    output = build()
    output["containers"][0][key] = value
    present = fields(observe(output))
    mapping = {
        "image": "containers[app].image",
        "env_count": "containers[app].env.count",
        "env_names_complete": "containers[app].env.names_complete",
    }

    assert mapping[key] not in present


def test_startup_vocabulary_is_enforced_and_exit_code_requires_unconditional():
    output = build()
    startup = output["containers"][0]["startup"]
    startup.update(entrypoint_kind="anything", static_analysis="maybe")

    present = fields(observe(output))

    assert "containers[app].startup.entrypoint_kind" not in present
    assert "containers[app].startup.static_analysis" not in present
    assert "containers[app].startup.static_exit_code" not in present

    output = build()
    output["containers"][0]["startup"].update(
        static_analysis="not_established", static_exit_code=1
    )
    assert "containers[app].startup.static_exit_code" not in fields(observe(output))

    output = build()
    output["containers"][0]["startup"]["static_exit_code"] = 999
    assert "containers[app].startup.static_exit_code" not in fields(observe(output))


def test_invalid_container_names_are_skipped():
    output = build()
    output["containers"][0]["name"] = "Bad Name]"

    assert not [o for o in observe(output) if o.field.startswith("containers[")]


def test_observation_count_is_bounded():
    output = build(
        pod=make_pod(
            [container(
                env=[client.V1EnvVar(name=f"V{i}", value="x") for i in range(500)]
            )]
        )
    )

    assert len(observe(output)) <= 120


# ----------------------------------------------------------------- grounding


def describe_output(exit_code=1):
    return {
        "namespace": NS,
        "name": POD,
        "phase": "Running",
        "containers": [
            {
                "name": "app",
                "ready": False,
                "restart_count": 5,
                "state": "waiting",
                "reason": "CrashLoopBackOff",
                "last_termination": {"exit_code": exit_code, "reason": "Error"},
            }
        ],
    }


def grounded_context(
    config=None, *, exit_code=1, describe=True, investigation_id="inv-g", max_steps=10
):
    context = InvestigationContext(
        investigation_id=investigation_id,
        user_text=f"Investigate the failing workload in namespace {NS}.",
        authorized_namespace=NS,
        max_steps=max_steps,
    )
    pods = ToolCall(name="k8s.get_pods", arguments={"namespace": NS})
    context.record_execution(
        request_id="r1", call=pods,
        result=ToolExecutionResult(
            tool=pods.name, status=ToolExecutionStatus.SUCCESS,
            output={"namespace": NS, "pods": [{"name": POD}]},
        ),
    )

    if describe:
        d = ToolCall(name="k8s.describe_pod", arguments={"namespace": NS, "pod": POD})
        context.record_execution(
            request_id="r2", call=d,
            result=ToolExecutionResult(
                tool=d.name, status=ToolExecutionStatus.SUCCESS,
                output=describe_output(exit_code),
            ),
        )

    context.record_execution(
        request_id="r3", call=call_for(),
        result=success(config if config is not None else build()),
    )

    return context


def report_for(context):
    snapshot = build_investigation_evidence_snapshot(context)
    report = build_grounded_report(snapshot)
    validate_report_snapshot(
        report, snapshot, expected_investigation_id=context.investigation_id
    )

    return snapshot, report


def titles(report):
    return [f.title for f in report.findings]


def test_report_has_workload_container_and_startup_findings():
    _, report = report_for(grounded_context())

    assert "Owning workload identified" in titles(report)
    assert "Container configuration observed" in titles(report)
    assert "Startup command exits unconditionally (static analysis)" in titles(report)

    config = next(f for f in report.findings if f.title == "Container configuration observed")
    assert "PLAIN_SETTING (literal value)" in config.description
    assert "DB_PASSWORD (Secret reference)" in config.description
    assert "never collected" in config.description
    assert_no_sentinels(report.model_dump_json())


def test_matching_exit_codes_produce_a_corroboration_finding_citing_all_evidence():
    snapshot, report = report_for(grounded_context(exit_code=1))

    finding = next(
        f for f in report.findings
        if f.title.startswith("Observed exit code matches")
    )
    cited = {
        item.evidence_id: item
        for item in snapshot.evidence
        if item.evidence_id in {r.evidence_id for r in finding.evidence}
    }

    assert finding.severity == "warning"
    assert {i.field for i in cited.values()} == {
        "containers[app].last_termination.exit_code",
        "containers[app].startup.static_analysis",
        "containers[app].startup.static_exit_code",
    }
    assert "environment variable values alone would not be expected" in finding.description
    # Evidence belongs to the same pod as the finding.
    assert {(i.namespace, i.pod) for i in cited.values()} == {(NS, POD)}


def test_different_exit_codes_produce_no_corroboration():
    _, report = report_for(grounded_context(exit_code=2))

    assert not any(t.startswith("Observed exit code matches") for t in titles(report))
    assert "Startup command exits unconditionally (static analysis)" in titles(report)


def test_missing_describe_evidence_produces_no_corroboration():
    _, report = report_for(grounded_context(describe=False))

    assert not any(t.startswith("Observed exit code matches") for t in titles(report))


def test_exit_code_from_another_pod_is_never_used_for_corroboration():
    context = grounded_context(describe=False)
    other = "other-7c9d5-zzzzz"
    d = ToolCall(name="k8s.describe_pod", arguments={"namespace": NS, "pod": other})
    context.record_execution(
        request_id="r9", call=d,
        result=ToolExecutionResult(
            tool=d.name, status=ToolExecutionStatus.SUCCESS,
            output={**describe_output(1), "name": other},
        ),
    )

    _, report = report_for(context)

    assert not any(t.startswith("Observed exit code matches") for t in titles(report))


def test_not_established_startup_yields_an_uncertainty_and_no_startup_finding():
    config = build(pod=make_pod([container(command=["/usr/bin/myapp"], args=None)]))
    _, report = report_for(grounded_context(config))

    assert not any("exits unconditionally" in t for t in titles(report))
    assert any(
        "could not be established by static analysis" in u
        and "not evidence that startup is correct" in u
        for u in report.uncertainties
    )


def test_complete_empty_environment_is_stated_precisely():
    config = build(pod=make_pod([container(env=None)]))
    _, report = report_for(grounded_context(config))
    finding = next(f for f in report.findings if f.title == "Container configuration observed")

    assert "declares no environment variables and no ConfigMap or Secret" in finding.description


def test_empty_environment_with_env_from_is_not_described_as_empty():
    config = build(
        pod=make_pod([container(env=None, env_from=[client.V1EnvFromSource(
            config_map_ref=client.V1ConfigMapEnvSource(name="bulk"))])])
    )
    _, report = report_for(grounded_context(config))
    finding = next(f for f in report.findings if f.title == "Container configuration observed")

    assert "declares no environment variables" not in finding.description
    assert "declares 0 environment variable(s)" in finding.description


def test_env_from_is_disclosed_as_an_uncertainty():
    config = build(
        pod=make_pod([container(env_from=[client.V1EnvFromSource(
            config_map_ref=client.V1ConfigMapEnvSource(name="bulk"))])])
    )
    _, report = report_for(grounded_context(config))

    assert any("may be incomplete" in u for u in report.uncertainties)
    assert any("may be loaded from ConfigMap or Secret" in f.description for f in report.findings)


def test_report_always_states_that_values_were_not_inspected():
    _, report = report_for(grounded_context())

    assert any(
        "never inspected" in u and "whether any variable is set correctly" in u
        for u in report.uncertainties
    )
    assert report.uncertainties[-1].startswith("Underlying failure causes")


def test_pods_without_configuration_evidence_get_no_configuration_findings():
    snapshot = build_investigation_evidence_snapshot(
        grounded_context(describe=False)
    )
    empty = build_investigation_evidence_snapshot(
        InvestigationContext(
            investigation_id="inv-empty", user_text="Investigate " + NS,
            authorized_namespace=NS,
        )
    )

    assert build_configuration_findings(empty) == []
    assert build_configuration_uncertainties(empty) == []
    assert build_configuration_findings(snapshot)


def test_uncertainty_list_is_bounded_without_losing_the_standing_caveat():
    many = [f"u{i}" for i in range(40)] + ["standing caveat"]

    bounded = bound_uncertainties(many)

    assert len(bounded) == MAX_UNCERTAINTIES
    assert bounded[-1] == "standing caveat"
    assert "omitted" in bounded[-2]
    assert bound_uncertainties(["a", "standing"]) == ["a", "standing"]


def test_report_with_many_pods_still_validates_and_discloses_truncation():
    # The step budget caps an investigation at 10 executions: one listing plus
    # nine configuration inspections.
    context = InvestigationContext(
        investigation_id="inv-many",
        user_text=f"Investigate the failing workload in namespace {NS}.",
        authorized_namespace=NS,
        max_steps=10,
    )
    pods = ToolCall(name="k8s.get_pods", arguments={"namespace": NS})
    context.record_execution(
        request_id="r0", call=pods,
        result=ToolExecutionResult(
            tool=pods.name, status=ToolExecutionStatus.SUCCESS,
            output={"namespace": NS, "pods": [{"name": POD}]},
        ),
    )
    for i in range(9):
        pod = f"extra-7c9d5-{i:05d}"
        cfg = build(
            pod=make_pod([container(command=["/usr/bin/x"], args=None)], name=pod)
        )
        context.record_execution(
            request_id=f"rx{i}", call=call_for(pod=pod), result=success(cfg)
        )

    snapshot, report = report_for(context)

    assert len(build_report_uncertainties_unbounded(snapshot)) > MAX_UNCERTAINTIES
    assert len(report.uncertainties) == MAX_UNCERTAINTIES
    assert any("omitted to bound the report" in u for u in report.uncertainties)
    assert report.uncertainties[-1].startswith("Underlying failure causes")


def build_report_uncertainties_unbounded(snapshot):
    from app.reports.grounding import build_report_uncertainties

    return build_report_uncertainties(snapshot)


# ------------------------------------------- hypothesis-stage integration


def test_hypothesis_prompt_separates_verified_configuration_from_untrusted_logs():
    from app.reports.hypotheses import HypothesisInput
    from app.reports.qwen_hypotheses import (
        HYPOTHESIS_SYSTEM_PROMPT,
        build_hypothesis_messages,
    )

    context = grounded_context()
    snapshot = build_investigation_evidence_snapshot(context)
    _, user = build_hypothesis_messages(
        HypothesisInput(
            snapshot=snapshot, log_entries=(), omitted_log_entries=0,
            authorized_namespace=NS,
        )
    )
    body = json.loads(user["content"])
    config_tools = {i["tool"] for i in body["verified_configuration_evidence"]["items"]}
    k8s_tools = {i["tool"] for i in body["kubernetes_verified_observations"]["items"]}

    assert config_tools == {WORKLOAD_CONFIG_TOOL}
    assert WORKLOAD_CONFIG_TOOL not in k8s_tools and k8s_tools
    assert body["verified_configuration_evidence"]["values_are_never_included"] is True
    assert "untrusted_logs" in body
    assert_no_sentinels(user["content"])

    # Instructions distinguish the four categories and require caution.
    for phrase in (
        "kubernetes_verified_observations",
        "verified_configuration_evidence",
        "untrusted_logs",
        "CLAIM",
        "UNVERIFIED",
        "If this list is empty, configuration has NOT been inspected",
        "omit",
    ):
        assert phrase in HYPOTHESIS_SYSTEM_PROMPT


def test_hypothesis_prompt_contains_no_demo_specific_content():
    from pathlib import Path

    for path in (
        "app/reports/qwen_hypotheses.py",
        "app/reports/hypotheses.py",
        "app/reports/config_grounding.py",
        "app/tools/workload_config.py",
    ):
        source = Path(path).read_text()
        for needle in ("PAYMENTS", "payments", "ai-ops-demo", "DB_HOST"):
            assert needle not in source, (path, needle)


def test_environment_names_with_digits_from_config_evidence_may_be_mentioned():
    from app.reports.hypotheses import HypothesisEvidenceRegistry, _check_text

    config = build(
        pod=make_pod([container(env=[client.V1EnvVar(name="DB_HOST_PRIMARY_1", value="x")])])
    )
    context = grounded_context(config)
    snapshot = build_investigation_evidence_snapshot(context)
    log = ToolCall(
        name="k8s.get_logs",
        arguments={"namespace": NS, "pod": POD, "container": "app"},
    )
    context.record_execution(
        request_id="r4", call=log,
        result=ToolExecutionResult(
            tool=log.name, status=ToolExecutionStatus.SUCCESS,
            output={
                "namespace": NS, "pod": POD, "container": "app", "tail": 200,
                "previous": False, "logs": "error: DB_HOST_PRIMARY_1 is required",
                "completeness": "bounded_unknown",
            },
        ),
    )
    registry = HypothesisEvidenceRegistry(
        investigation_id=context.investigation_id,
        authorized_namespace=NS,
        snapshot=snapshot,
        log_entries=context.log_entries,
    )

    assert "DB_HOST_PRIMARY_1" in _check_text(
        "The variable DB_HOST_PRIMARY_1 may be unset.", registry
    )
