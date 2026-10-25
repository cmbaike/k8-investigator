"""Synthetic transcription checks for the local speech path.

Piper speaks each approved sentence. The samples are then carried at 48 kHz,
the browser's usual rate, and decoded by the same WAV path a recording uses.
Nothing is written to disk. The test skips when the local voice or Whisper
weights are absent, so a normal environment without those files still runs.
"""

import io
import re
import wave

import numpy as np
import pytest
from piper import SynthesisConfig

from app.speech.audio import decode_wav
from app.speech.runtime import LocalSpeechRuntime, speech_home

PHRASES = (
    "Investigate the health of the current namespace.",
    "Why is payments-api failing?",
    "Investigate the bad-readiness Deployment.",
    "Check why the container was OOMKilled.",
    "The pod is experiencing CrashLoopBackOff.",
    "Investigate ImagePullBackOff in ai-ops-demo.",
)
REPORTED = "What is the health of the namespace of the current namespace?"
CONTROL = "What time is the meeting tomorrow?"
EXACT_TERMS = ("OOMKilled", "CrashLoopBackOff", "ImagePullBackOff")


def _word_error(reference: str, hypothesis: str) -> float:
    left, right = _words(reference), _words(hypothesis)

    if not left:
        return 0.0 if not right else 1.0

    previous = list(range(len(right) + 1))

    for index, word in enumerate(left, 1):
        current = [index]

        for column, other in enumerate(right, 1):
            current.append(
                min(
                    previous[column] + 1,
                    current[column - 1] + 1,
                    previous[column - 1] + (word != other),
                )
            )

        previous = current

    return previous[-1] / len(left)


def _words(text: str) -> list[str]:
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text)
    text = text.replace("-", " ")
    text = re.sub(r"[^A-Za-z0-9 ]+", " ", text)

    return re.sub(r"\s+", " ", text).strip().lower().split()


def _speak(runtime, text: str) -> tuple[np.ndarray, int]:
    """Deterministic local speech, so the recording does not change between runs."""
    buffer = io.BytesIO()

    with wave.open(buffer, "wb") as wav_file:
        runtime._piper().synthesize_wav(
            text,
            wav_file,
            syn_config=SynthesisConfig(noise_scale=0.0, noise_w_scale=0.0),
        )

    return _read(buffer.getvalue())


def _read(data: bytes) -> tuple[np.ndarray, int]:
    with wave.open(io.BytesIO(data), "rb") as wav_file:
        rate = wav_file.getframerate()
        frames = wav_file.readframes(wav_file.getnframes())

    return np.frombuffer(frames, dtype=np.int16).astype(np.float32) / 32768.0, rate


def _wav(samples: np.ndarray, rate: int) -> bytes:
    pcm = (np.clip(samples, -1, 1) * 32767).astype(np.int16)
    buffer = io.BytesIO()

    with wave.open(buffer, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(rate)
        wav_file.writeframes(pcm.tobytes())

    return buffer.getvalue()


def _browser_samples(native: np.ndarray, rate: int, noise: np.ndarray | None = None) -> list[float]:
    """48 kHz 16-bit WAV, then the production decoder. Optional noise is added
    at the microphone rate, before that decode."""
    length = max(1, int(len(native) * 48_000 / rate))
    carrier = np.interp(np.linspace(0, len(native) - 1, length), np.arange(len(native)), native)

    if noise is not None:
        carrier = carrier + noise

    return decode_wav(_wav(carrier.astype(np.float32), 48_000))


def _plain(model, samples: list[float]) -> str:
    from app.speech.runtime import _float32

    segments, _info = model.transcribe(
        _float32(samples),
        language="en",
        task="transcribe",
        beam_size=1,
        temperature=0.0,
        vad_filter=False,
        condition_on_previous_text=False,
        without_timestamps=True,
    )

    return " ".join(segment.text for segment in segments).strip()


@pytest.fixture(scope="module")
def runtime():
    voice = speech_home() / "voices" / "en_US-ljspeech-medium.onnx"
    weights = speech_home() / "whisper" / "models--Systran--faster-whisper-base.en"

    if not voice.is_file() or not weights.exists():
        pytest.skip("local speech models are not installed")

    pytest.importorskip("faster_whisper")
    pytest.importorskip("piper")

    return LocalSpeechRuntime()


def test_browser_audio_path_keeps_ordinary_words_and_condition_names(runtime):
    errors = []

    for phrase in PHRASES:
        native, rate = _speak(runtime, phrase)
        transcript = runtime.transcribe(_browser_samples(native, rate), 16_000)
        errors.append(_word_error(phrase, transcript))

        for term in EXACT_TERMS:
            if term in phrase:
                assert term in transcript

    assert sum(errors) / len(errors) <= 0.06
    assert errors[-1] <= 0.34


def test_noisy_namespace_is_not_split_and_hints_are_not_invented(runtime):
    native, rate = _speak(runtime, REPORTED)
    length = max(1, int(len(native) * 48_000 / rate))
    carrier = np.interp(
        np.linspace(0, len(native) - 1, length), np.arange(len(native)), native
    ).astype(np.float32)
    level = float(np.sqrt(np.mean(carrier**2)))
    # Seed 7 at 15 dB is the measured sample that the current decoder, without
    # a vocabulary hint, transcribes exactly as the reported failure.
    noise = np.random.default_rng(7).normal(
        0, level / (10 ** (15 / 20)), size=carrier.shape
    ).astype(np.float32)
    samples = decode_wav(_wav(carrier + noise, 48_000))
    baseline = _plain(runtime._whisper(), samples)
    improved = runtime.transcribe(samples, 16_000)

    assert "name space" in baseline.lower()
    assert "namespace" in improved.lower()
    assert "name space" not in improved.lower()

    control_audio, control_rate = _speak(runtime, CONTROL)
    control = runtime.transcribe(_browser_samples(control_audio, control_rate), 16_000).lower()

    assert _word_error(CONTROL, control) == 0
    for term in ("namespace", *EXACT_TERMS):
        assert term.lower() not in control
