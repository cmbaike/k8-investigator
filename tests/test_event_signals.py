"""Fixed-vocabulary classification of untrusted scheduler/kubelet messages."""

import pytest

from app.tools.event_signals import (
    ALL_SIGNALS,
    MAX_MESSAGE_CHARS,
    MAX_SIGNALS,
    SIGNAL_NAME,
    classify_event,
    classify_scheduling_message,
    signals_allowed,
    source_allowed,
    volume_names,
)

SCHEDULER = "default-scheduler"


@pytest.mark.parametrize(
    "message, expected",
    [
        ("0/3 nodes are available: 3 Insufficient cpu.", "insufficient_cpu"),
        ("0/1 nodes are available: 1 Insufficient memory.", "insufficient_memory"),
        (
            "0/2 nodes are available: 2 node(s) didn't match Pod's node affinity/selector.",
            "node_selector_mismatch",
        ),
        (
            "0/1 nodes are available: 1 node(s) had untolerated taint {k: v}.",
            "untolerated_taint",
        ),
        (
            "0/1 nodes are available: 1 node(s) didn't find available persistent volumes to bind.",
            "unbound_volume_claim",
        ),
    ],
)
def test_scheduler_messages_map_to_fixed_signals(message, expected):
    assert expected in classify_event("FailedScheduling", message, SCHEDULER)
    assert expected in classify_scheduling_message(message)


def test_unrecognised_message_yields_no_signal():
    assert classify_event("FailedScheduling", "something entirely different", SCHEDULER) == ()


def test_every_signal_is_a_bounded_fixed_vocabulary_name():
    assert ALL_SIGNALS and all(SIGNAL_NAME.fullmatch(name) for name in ALL_SIGNALS)


def test_signals_are_bounded_per_message():
    message = " ".join(
        [
            "Insufficient cpu", "Insufficient memory", "Insufficient ephemeral-storage",
            "Too many pods", "untolerated taint", "didn't match Pod's node selector",
        ]
    )

    assert len(classify_scheduling_message(message)) <= MAX_SIGNALS


def test_message_is_cut_before_matching():
    padded = "x" * (MAX_MESSAGE_CHARS + 10) + " Insufficient cpu"

    assert classify_scheduling_message(padded) == ()


@pytest.mark.parametrize("message", [None, 5, b"Insufficient cpu", ["Insufficient cpu"]])
def test_non_string_messages_are_ignored(message):
    assert classify_scheduling_message(message) == ()
    assert classify_event("FailedScheduling", message, SCHEDULER) == ()


def test_signal_is_only_accepted_from_the_component_that_emits_the_reason():
    message = "0/1 nodes are available: 1 Insufficient memory."

    assert classify_event("FailedScheduling", message, "kubelet") == ()
    assert classify_event("FailedScheduling", message, None) == ()
    assert classify_event("FailedScheduling", message, "x" * 200) == ()
    assert classify_event("FailedScheduling", message, "my-custom-scheduler") != ()
    assert source_allowed("FailedMount", "kubelet")
    assert not source_allowed("FailedMount", SCHEDULER)


def test_a_signal_is_only_valid_for_its_own_reason():
    assert signals_allowed("FailedScheduling", "insufficient_cpu")
    assert not signals_allowed("FailedMount", "insufficient_cpu")
    assert not signals_allowed("Unhealthy", "config_map_not_found")
    assert not signals_allowed("Unknown", "insufficient_cpu")
    # Cross-reason injection: scheduler wording on a kubelet reason gives nothing.
    assert classify_event("Unhealthy", "Insufficient cpu", "kubelet") == ()


def test_mount_messages_are_classified_without_keeping_object_names():
    message = 'MountVolume.SetUp failed for volume "cfg" : configmap "private-name" not found'
    signals = classify_event("FailedMount", message, "kubelet")

    assert "config_map_not_found" in signals and "mount_setup_failed" in signals
    assert "private-name" not in " ".join(signals)


def test_secret_not_found_is_classified_by_kind_only():
    message = 'MountVolume.SetUp failed for volume "creds" : secret "db-password" not found'

    assert "secret_not_found" in classify_event("FailedMount", message, "kubelet")


def test_probe_failure_kind_is_read_from_the_start_of_the_message():
    assert classify_event(
        "Unhealthy", "Liveness probe failed: HTTP probe failed with statuscode: 404", "kubelet"
    ) == ("liveness_probe_failed",)
    assert classify_event(
        "Unhealthy", "Readiness probe failed: connection refused", "kubelet"
    ) == ("readiness_probe_failed",)
    # A message that merely MENTIONS a liveness probe is not a liveness failure.
    assert classify_event(
        "Unhealthy", "Readiness probe failed: the liveness probe failed earlier", "kubelet"
    ) == ("readiness_probe_failed",)
    assert classify_event("Unhealthy", "see Liveness probe failed", "kubelet") == ()


def test_liveness_restart_is_read_from_the_killing_event():
    message = "Container app failed liveness probe, will be restarted"

    assert classify_event("Killing", message, "kubelet") == ("liveness_restart",)


def test_volume_names_must_be_declared_by_the_pod_itself():
    message = 'MountVolume.SetUp failed for volume "cfg" : not found; for volume "invented"'

    assert volume_names(message, ["cfg", "data"]) == ("cfg",)
    assert volume_names(message, []) == ()
    assert volume_names(None, ["cfg"]) == ()


def test_unmounted_volume_list_is_confirmed_against_declared_names():
    message = "Unable to attach or mount volumes: unmounted volumes=[cfg other], unattached"

    assert volume_names(message, ["cfg"]) == ()  # "[cfg other]" is one token: not a name
    assert volume_names("unmounted volumes=[cfg,data]", ["cfg", "data", "x"]) == ("cfg", "data")
