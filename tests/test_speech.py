"""Speech transcription, spoken briefings, and the limits around both."""

import io
import logging
import math
import struct
import threading
import time
import wave
from pathlib import Path
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api import app
from app.reports.models import AIHypothesis, EvidenceReference, HypothesisResource, InvestigationFinding, InvestigationReport
from app.security.api_keys import APIKeyPrincipal
from app.security.dependencies import get_demo_principal
from app.speech.audio import MAX_AUDIO_BYTES, decode_wav
from app.speech.briefing import build_spoken_briefing
from app.speech.gate import ExecutionGate
from app.speech.problems import SpeechProblem
from app.speech.runtime import SpeechRuntime, clean_transcript, set_runtime
from app.tools.models import ToolRisk
from app.tools.registry import TOOLS
NS = "ai-ops-demo"
PRINCIPAL = APIKeyPrincipal(principal_id="demo", allowed_namespaces=frozenset({NS}))


class FakeRuntime(SpeechRuntime):
    def __init__(self) -> None:
        self.transcript = "Investigate why the bad-readiness workload is failing in ai-ops-demo."
        self.calls: list[tuple] = []
        self.available = True
        self.problem: SpeechProblem | None = None

    def transcribe(self, samples: list[float], sample_rate: int) -> str:
        self.calls.append(("transcribe", sample_rate, len(samples)))

        if self.problem is not None:
            raise self.problem

        return self.transcript

    def synthesize(self, text: str) -> bytes:
        self.calls.append(("synthesize", text))

        if self.problem is not None:
            raise self.problem

        return wav_bytes(seconds=0.3)

    def synthesis_available(self) -> bool:
        return self.available


@pytest.fixture
def runtime():
    fake = FakeRuntime()
    set_runtime(fake)

    try:
        yield fake
    finally:
        set_runtime(None)


@pytest.fixture
def client():
    app.dependency_overrides[get_demo_principal] = lambda: PRINCIPAL

    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_demo_principal, None)


def sign_in(client):
    return {"allowed_namespaces": [NS]}


def csrf(info):
    return {}


def wav_bytes(*, seconds=0.5, rate=16000, amplitude=8000) -> bytes:
    count = int(seconds * rate)
    frames = bytearray()

    for index in range(count):
        sample = 0 if amplitude == 0 else int(amplitude * math.sin(2 * math.pi * 440 * index / rate))
        frames += struct.pack("<h", sample)

    buffer = io.BytesIO()

    with wave.open(buffer, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(rate)
        wav_file.writeframes(bytes(frames))

    return buffer.getvalue()


def post_audio(client, info, data: bytes, content_type="audio/wav"):
    return client.post(
        "/api/speech/transcribe",
        files={"audio": ("request.wav", data, content_type)},
        headers=csrf(info),
    )


def finding(**overrides) -> InvestigationFinding:
    fields = {
        "title": "Container is running but not ready",
        "description": (
            "Container 'app' is running but Kubernetes reports it is not ready. "
            "Resource: namespace 'ai-ops-demo', pod 'bad-readiness-abc'."
        ),
        "severity": "critical",
        "evidence": [EvidenceReference(evidence_id="ev-0005")],
    }
    fields.update(overrides)

    return InvestigationFinding(**fields)


def hypothesis(**overrides) -> AIHypothesis:
    fields = {
        "explanation": "Possible explanation, unverified.",
        "possible_explanation": "The readiness probe may be failing because its path is wrong.",
        "not_yet_verified": "The probe path has not been checked.",
        "evidence_refs": ["ev-0005"],
        "resource": HypothesisResource(namespace=NS, pod="bad-readiness-abc", container="app"),
        "verification_check": "Inspect the declared probe through read-only describe output.",
    }
    fields.update(overrides)

    return AIHypothesis(**fields)


def report(**overrides) -> InvestigationReport:
    fields = {
        "investigation_id": "inv-speech",
        "summary": "Verified findings only.",
        "findings": [finding()],
        "uncertainties": [],
        "suggested_checks": [],
        "ai_hypotheses": [hypothesis()],
    }
    fields.update(overrides)

    return InvestigationReport(**fields)


def row(**overrides) -> dict:
    value = {
        "investigation_id": "inv-speech",
        "authorized_namespace": NS,
        "status": "completed",
        "stop_reason": "provider_finished",
        "user_text": "Investigate deployment/bad-readiness. Why is this workload unhealthy?",
    }
    value.update(overrides)

    return value


def patched(row_value, report_value=None):
    repository = Mock()
    repository.get_investigation_row_for_namespaces.return_value = row_value
    repository.get_report.return_value = report_value

    return patch("app.web.routes.InvestigationRepository", return_value=repository), repository


# --------------------------------------------------------------- transcription


def test_transcription_does_not_require_a_session(client, runtime):
    response = client.post(
        "/api/speech/transcribe",
        files={"audio": ("request.wav", wav_bytes(), "audio/wav")},
    )

    assert response.status_code == 200
    assert runtime.calls[0][0] == "transcribe"


def test_transcription_returns_text_and_does_not_run_kubernetes(client, runtime):
    info = sign_in(client)
    repository = Mock()

    with (
        patch("app.web.routes.InvestigationRepository", return_value=repository),
        patch("app.tools.executor.execute_tool_call") as execute,
    ):
        response = post_audio(client, info, wav_bytes())

    assert response.status_code == 200, response.text
    assert response.json() == {
        "transcript": "Investigate why the bad-readiness workload is failing in ai-ops-demo."
    }
    assert response.headers["cache-control"] == "no-store"
    assert runtime.calls[0][0] == "transcribe"
    assert runtime.calls[0][1] == 16_000
    repository.assert_not_called()
    execute.assert_not_called()


def post_proposal(client, info, transcript, namespace=NS):
    return client.post(
        "/api/speech/proposal",
        json={"transcript": transcript, "namespace": namespace},
        headers=csrf(info),
    )


def test_a_proposal_uses_the_investigation_classifier_and_runs_nothing(client):
    info = sign_in(client)

    with patch("app.tools.executor.execute_tool_call") as execute:
        namespace = post_proposal(client, info, "Investigate the namespace health")
        targeted = post_proposal(
            client, info, "Investigate why the bad-readiness workload is failing in ai-ops-demo."
        )
        kind = post_proposal(client, info, "Investigate pod/bad-readiness")
        misheard = post_proposal(client, info, "Why is bad-readyness failing?")
        ambiguous = post_proposal(client, info, "Why is it failing?")
        widened = post_proposal(
            client, info, "Why is payments-api failing, and is everything else healthy?"
        )
        other_namespace = post_proposal(client, info, "Investigate the health of the prod namespace")
        mutation = post_proposal(client, info, "Investigate it, then restart the pod")
        denied = post_proposal(client, info, "Investigate the namespace health", namespace="kube-system")

    assert namespace.status_code == 200
    assert namespace.json() == {"outcome": "namespace", "name": None, "kind": None, "code": None}
    assert namespace.headers["cache-control"] == "no-store"
    assert targeted.json() == {
        "outcome": "workload",
        "name": "bad-readiness",
        "kind": None,
        "code": None,
    }
    assert kind.json()["outcome"] == "workload"
    assert kind.json()["name"] == "bad-readiness"
    assert kind.json()["kind"] == "Pod"
    assert misheard.json() == {"outcome": "workload", "name": "bad-readyness", "kind": None, "code": None}
    assert ambiguous.json()["outcome"] == "clarify"
    assert ambiguous.json()["code"] == "scope_unspecified"
    assert ambiguous.json()["name"] is None
    assert widened.json()["code"] == "ambiguous_scope"
    assert other_namespace.json()["code"] == "namespace_conflict"
    assert mutation.json()["code"] == "state_change"
    assert denied.status_code == 403
    execute.assert_not_called()


def test_a_proposal_does_not_require_a_session(client):
    body = {"transcript": "Investigate the namespace health", "namespace": NS}
    response = client.post("/api/speech/proposal", json=body)

    assert response.status_code == 200
    assert response.json()["outcome"] in {"namespace", "workload", "clarify"}


def test_a_misheard_name_is_returned_as_text_and_not_executed(client, runtime):
    runtime.transcript = "Investigate why the bad-readyness workload is failing."
    info = sign_in(client)
    response = post_audio(client, info, wav_bytes())

    assert response.status_code == 200
    assert response.json()["transcript"] == runtime.transcript
    assert len(runtime.calls) == 1


def test_empty_invalid_oversized_and_unsupported_audio_never_reach_the_model(client, runtime):
    info = sign_in(client)

    empty = post_audio(client, info, wav_bytes(seconds=0.1))
    silent = post_audio(client, info, wav_bytes(seconds=1, amplitude=0))
    invalid = post_audio(client, info, b"RIFFxxxxWAVE" + b"not-audio" * 8)
    too_long = post_audio(client, info, wav_bytes(seconds=31, rate=8000))
    unsupported = post_audio(client, info, wav_bytes(), content_type="audio/webm")
    oversized = post_audio(client, info, b"R" * (MAX_AUDIO_BYTES + 1))

    assert empty.status_code == 400 and "empty" in empty.json()["detail"]
    assert silent.status_code == 400 and "empty" in silent.json()["detail"]
    assert invalid.status_code == 400
    assert too_long.status_code == 400 and "too long" in too_long.json()["detail"]
    assert unsupported.status_code == 415
    assert oversized.status_code == 413
    assert runtime.calls == []


def test_wav_with_a_parameter_on_the_media_type_is_accepted(client, runtime):
    info = sign_in(client)
    response = post_audio(client, info, wav_bytes(), content_type="audio/wav; charset=binary")

    assert response.status_code == 200
    assert runtime.calls


def test_an_unavailable_transcriber_is_a_fixed_error(client, runtime):
    runtime.problem = SpeechProblem(503, "Speech transcription is unavailable.")
    info = sign_in(client)
    response = post_audio(client, info, wav_bytes())

    assert response.status_code == 503
    assert response.json()["detail"] == "Speech transcription is unavailable."
    assert "traceback" not in response.text.lower()


def test_transcription_does_not_log_audio_or_the_transcript(client, runtime, caplog):
    caplog.set_level(logging.DEBUG)
    info = sign_in(client)
    payload = wav_bytes()
    response = post_audio(client, info, payload)

    assert response.status_code == 200
    assert "bad-readiness" not in caplog.text
    assert payload[:24].hex() not in caplog.text


def test_clean_transcript_drops_controls_and_limits_length():
    assert clean_transcript("hello\x00  there") == "hello there"
    assert len(clean_transcript("a" * 5000)) == 4000


# --------------------------------------------------------------------- briefing


def _briefing(client, info, row_value, report_value):
    context, _repository = patched(row_value, report_value)

    with context:
        response = client.get(f"/api/investigations/{row_value['investigation_id']}/briefing")

    return response


def test_briefing_for_a_verified_finding_keeps_the_hypothesis_unverified(client, runtime):
    info = sign_in(client)
    body = report()
    response = _briefing(client, info, row(), body)

    assert response.status_code == 200, response.text
    text = response.json()["text"]
    assert response.json()["speech_available"] is True
    assert "is running but not ready" in text
    assert "readiness is false" in text
    assert "A possible explanation is" in text
    assert text.index("A possible explanation") < text.index("path is wrong")
    assert "Next, inspect the declared probe" in text
    assert "The primary verified finding is" not in text
    assert "It suggests" not in text
    assert "A read-only check to consider" not in text
    assert "unverified, not a verified finding" not in text
    assert "Spoken briefing" not in text
    assert text.endswith(".")
    assert 40 <= len(text.split()) <= 90
    assert "ev-" not in text


def test_briefing_with_no_accepted_hypothesis_does_not_invent_one(client, runtime):
    info = sign_in(client)
    response = _briefing(client, info, row(), report(ai_hypotheses=[]))
    text = response.json()["text"]

    assert response.status_code == 200
    assert "The underlying cause hasn't been confirmed." in text
    assert "A possible explanation" not in text
    assert "It suggests" not in text


def test_briefing_does_not_treat_a_missing_target_as_a_diagnosed_failure(client, runtime):
    info = sign_in(client)
    missing = report(
        uncertainties=[
            "The requested Deployment 'missing' could not be found: none of the "
            "1 pod(s) listed in the namespace is controlled by a workload with that name. "
            "No other workload was investigated in its place."
        ],
        ai_hypotheses=[],
    )
    text = _briefing(client, info, row(), missing).json()["text"]

    assert "could not be found" in text
    assert "Nothing else was investigated." in text
    assert "primary verified finding" not in text
    assert "running but not ready" not in text
    assert "A possible explanation" not in text


def test_briefing_says_when_evidence_does_not_establish_a_failure(client, runtime):
    info = sign_in(client)
    text = _briefing(
        client,
        info,
        row(),
        report(findings=[finding(title="Pod discovered", severity="info")], ai_hypotheses=[]),
    ).json()["text"]

    assert "did not establish a warning or critical problem" in text
    assert "Pod discovered" not in text


def test_briefing_for_a_failed_investigation_invents_nothing(client, runtime):
    info = sign_in(client)
    context, repository = patched(row(status="failed", stop_reason="tool_failed"), report())

    with context:
        response = client.get("/api/investigations/inv-speech/briefing")

    text = response.json()["text"]
    assert response.status_code == 200
    assert "The investigation of Deployment bad-readiness failed." in text
    assert "No finding was established." in text
    assert "no report was produced." in text
    assert "running but not ready" not in text
    assert "A possible explanation" not in text
    assert "primary verified finding" not in text
    repository.get_report.assert_not_called()


def test_partial_coverage_is_described_as_partial(client, runtime):
    info = sign_in(client)
    text = _briefing(
        client, info, row(stop_reason="step_budget_exhausted"), report(ai_hypotheses=[])
    ).json()["text"]

    assert "Coverage is incomplete" in text
    assert "step budget" in text


def test_sensitive_evidence_and_commands_are_not_spoken(client, runtime):
    info = sign_in(client)
    body = report(
        findings=[
            finding(
                description=(
                    "Container app is not ready and password=s3cret appears beside ev-0005 "
                    "with AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA in the same sentence"
                )
            )
        ],
        ai_hypotheses=[
            hypothesis(
                possible_explanation="The path may be wrong. password=hunter2 token=abc",
                verification_check="Run kubectl delete pod bad-readiness",
            )
        ],
        suggested_checks=["Run kubectl apply -f deploy.yaml"],
    )
    text = _briefing(client, info, row(), body).json()["text"]

    assert "A possible explanation is" in text or "hasn't been confirmed" in text
    for secret in ("s3cret", "hunter2", "ev-0005", "kubectl", "AAAAAAAAAAAAAAAA"):
        assert secret not in text


def test_audio_speaks_the_briefing_text_and_rejects_client_supplied_words(client, runtime):
    info = sign_in(client)
    context, _repository = patched(row(), report())

    with context:
        briefing = client.get("/api/investigations/inv-speech/briefing")
        audio = client.get("/api/investigations/inv-speech/briefing/audio")
        rejected = client.post(
            "/api/investigations/inv-speech/briefing/audio",
            json={"text": "kubectl delete pod bad-readiness password=hunter2"},
            headers=csrf(info),
        )

    assert briefing.status_code == 200
    assert audio.status_code == 200
    assert audio.headers["content-type"].startswith("audio/wav")
    assert audio.headers["cache-control"] == "no-store"
    assert audio.content.startswith(b"RIFF")
    assert runtime.calls[-1] == ("synthesize", briefing.json()["text"])
    assert rejected.status_code == 405


def test_unavailable_synthesis_still_returns_the_briefing(client, runtime):
    runtime.available = False
    runtime.problem = SpeechProblem(503, "Speech synthesis is unavailable.")
    info = sign_in(client)
    context, _repository = patched(row(), report())

    with context:
        briefing = client.get("/api/investigations/inv-speech/briefing")
        audio = client.get("/api/investigations/inv-speech/briefing/audio")

    assert briefing.status_code == 200
    assert briefing.json()["speech_available"] is False
    assert "not ready" in briefing.json()["text"]
    assert audio.status_code == 503
    assert "hunter2" not in audio.text


def test_an_unknown_investigation_is_not_found(client, runtime):
    info = sign_in(client)
    context, _repository = patched(None, None)

    with context:
        response = client.get(f"/api/investigations/{uuid4()}/briefing", headers=csrf(info))

    assert response.status_code == 404


def test_builder_covers_pending_and_direct_call_without_a_model():
    text = build_spoken_briefing(
        status="pending",
        stop_reason=None,
        namespace=NS,
        scope_mode="workload",
        scope_kind="Deployment",
        scope_name="bad-readiness",
        report=None,
    )

    assert "still pending" in text
    assert "bad-readiness" in text
    assert "There is no finding yet." in text


# ----------------------------------------------------------------------- limits


def test_the_gate_times_out_and_holds_the_only_slot():
    started = threading.Event()
    release = threading.Event()

    def slow():
        started.set()
        assert release.wait(2)

        return "done"

    gate = ExecutionGate(timeout=0.05, busy="busy", timed_out="timeout", unavailable="unavailable")

    try:
        with pytest.raises(SpeechProblem) as timed:
            gate.run(slow)

        assert timed.value.status == 504
        assert started.wait(1)

        with pytest.raises(SpeechProblem) as busy:
            gate.run(lambda: "no")

        assert busy.value.status == 503
        assert busy.value.detail == "busy"
        release.set()
        deadline = time.time() + 2

        while time.time() < deadline:
            try:
                assert gate.run(lambda: "ok") == "ok"
                break
            except SpeechProblem:
                time.sleep(0.02)
        else:
            raise AssertionError("the speech slot stayed busy")
    finally:
        release.set()
        gate.close()


def test_the_gate_hides_engine_exception_text():
    gate = ExecutionGate(timeout=1, busy="busy", timed_out="timeout", unavailable="unavailable")

    def boom():
        raise RuntimeError("password=hunter2")

    try:
        with pytest.raises(SpeechProblem) as caught:
            gate.run(boom)
    finally:
        gate.close()

    assert caught.value.status == 503
    assert "hunter2" not in caught.value.detail


def test_decode_rejects_a_non_wav_payload():
    with pytest.raises(SpeechProblem) as caught:
        decode_wav(b"not a wav file at all, just text")

    assert caught.value.status == 400


def test_vocabulary_hint_names_terms_not_workloads():
    from app.speech.runtime import _VOCABULARY_HINT

    assert "namespace" in _VOCABULARY_HINT
    assert "pod" in _VOCABULARY_HINT.split()
    assert "OOMKilled" in _VOCABULARY_HINT
    assert "CrashLoopBackOff" in _VOCABULARY_HINT
    assert "ImagePullBackOff" in _VOCABULARY_HINT

    for banned in ("payments-api", "bad-readiness", "ai-ops-demo", "kubectl", "http"):
        assert banned not in _VOCABULARY_HINT


def test_speech_code_does_not_call_kubernetes_or_a_remote_provider_or_add_tools():
    root = Path(__file__).resolve().parents[1] / "app" / "speech"
    text = "\n".join(path.read_text() for path in root.glob("*.py"))

    for needle in (
        "execute_tool_call",
        "openai",
        "httpx",
        "import requests",
        "delete_pod",
        "restart_deployment",
        "websocket",
        "subprocess",
    ):
        assert needle not in text

    changing = {name for name, tool in TOOLS.items() if tool.risk is not ToolRisk.READ_ONLY}

    assert changing == {"k8s.restart_deployment", "k8s.delete_pod"}

    from app.web.routes import transcribe_speech
    import inspect

    source = inspect.getsource(transcribe_speech)

    assert "execute_tool" not in source
    assert "get_runtime().transcribe" in source

    from app.web.routes import propose_speech

    proposal_source = inspect.getsource(propose_speech)

    assert "execute_tool" not in proposal_source
    assert "get_runtime" not in proposal_source
