"""Local speech engines.

Hardware this build targets: 32 CPU cores, no usable NVIDIA device, so both
engines run on CPU.

Speech to text: faster-whisper (MIT) with an OpenAI Whisper English model
(MIT). The default is ``base.en`` at int8, which fits a short request on CPU.
English is selected explicitly, so language detection does not run. A short
generic vocabulary hint biases spelling of terms such as ``namespace``; it is
not applied as a rewrite after decoding. ``SPEECH_STT_MODEL=small.en`` selects
the larger English model when it has been placed locally. Audio is not uploaded
anywhere. Weights are read from
disk; a download happens only when ``SPEECH_ALLOW_MODEL_DOWNLOAD=1``.

Speech synthesis: Piper (``piper-tts`` 1.8, GPL-3.0) and the English voice
``en_US-ljspeech-medium``. That voice is trained on the public-domain LJ
Speech dataset, so it can be used in a commercial demo. The lessac voice is
not used: its source audio is under a research-only licence. Voice files are
loaded from ``.local/speech/voices`` and are not fetched during a request.
The Piper package that installs on this Python is GPL-3.0; the older MIT
Piper line does not. Redistributing this process as proprietary software
needs a separate licence review. Running it locally does not send audio out.

There is no external speech provider. A URL in the environment is ignored.
"""

import importlib.util
import logging
import os
import re
import threading
from pathlib import Path

from app.speech.gate import ExecutionGate
from app.speech.problems import (
    SYNTHESIS_BUSY,
    SYNTHESIS_TIMEOUT,
    SYNTHESIS_UNAVAILABLE,
    TRANSCRIPTION_BUSY,
    TRANSCRIPTION_TIMEOUT,
    TRANSCRIPTION_UNAVAILABLE,
    SpeechProblem,
)

log = logging.getLogger("app.speech")

MAX_TRANSCRIPT_CHARS = 4_000
MAX_SYNTH_CHARS = 900
MAX_WAV_BYTES = 4_000_000
_STT_TIMEOUT_S = 45.0
_TTS_TIMEOUT_S = 20.0
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_SPACE = re.compile(r"\s+")
# Spelling bias for the decoder. These are generic Kubernetes words the English
# model otherwise splits ("name space") or respells. The hint is not a list of
# workloads or namespaces, and the returned text is still the decoded words.
_VOCABULARY_HINT = "namespace pod OOMKilled CrashLoopBackOff ImagePullBackOff"


def speech_home() -> Path:
    configured = os.environ.get("SPEECH_HOME")

    if configured:
        return Path(configured)

    return Path(__file__).resolve().parents[2] / ".local" / "speech"


def _voice_path() -> Path:
    configured = os.environ.get("SPEECH_TTS_MODEL")

    if configured:
        return Path(configured)

    return speech_home() / "voices" / "en_US-ljspeech-medium.onnx"


def clean_transcript(text: str) -> str:
    text = _CONTROL.sub(" ", text)
    text = _SPACE.sub(" ", text).strip()

    return text[:MAX_TRANSCRIPT_CHARS]


class SpeechRuntime:
    """The operations the routes need. Tests substitute their own."""

    def transcribe(self, samples: list[float], sample_rate: int) -> str:
        raise SpeechProblem(503, TRANSCRIPTION_UNAVAILABLE)

    def synthesize(self, text: str) -> bytes:
        raise SpeechProblem(503, SYNTHESIS_UNAVAILABLE)

    def synthesis_available(self) -> bool:
        return False


class LocalSpeechRuntime(SpeechRuntime):
    def __init__(self) -> None:
        self._stt = ExecutionGate(
            timeout=_STT_TIMEOUT_S,
            busy=TRANSCRIPTION_BUSY,
            timed_out=TRANSCRIPTION_TIMEOUT,
            unavailable=TRANSCRIPTION_UNAVAILABLE,
        )
        self._tts = ExecutionGate(
            timeout=_TTS_TIMEOUT_S,
            busy=SYNTHESIS_BUSY,
            timed_out=SYNTHESIS_TIMEOUT,
            unavailable=SYNTHESIS_UNAVAILABLE,
        )
        self._model = None
        self._voice = None
        self._load_lock = threading.Lock()

    def synthesis_available(self) -> bool:
        return _voice_path().is_file() and importlib.util.find_spec("piper") is not None

    def transcribe(self, samples: list[float], sample_rate: int) -> str:
        if sample_rate != 16_000 or not samples:
            raise SpeechProblem(503, TRANSCRIPTION_UNAVAILABLE)

        def call() -> str:
            model = self._whisper()
            array = _float32(samples)
            segments, _info = model.transcribe(
                array,
                language="en",
                task="transcribe",
                beam_size=1,
                temperature=0.0,
                vad_filter=False,
                condition_on_previous_text=False,
                without_timestamps=True,
                hotwords=_VOCABULARY_HINT,
            )

            return clean_transcript(" ".join(segment.text for segment in segments))

        try:
            return self._stt.run(call)
        except SpeechProblem:
            raise
        except Exception:
            log.warning("speech transcription failed: %s", "runtime")
            raise SpeechProblem(503, TRANSCRIPTION_UNAVAILABLE) from None

    def synthesize(self, text: str) -> bytes:
        spoken = clean_transcript(text)[:MAX_SYNTH_CHARS]

        if not spoken:
            raise SpeechProblem(503, SYNTHESIS_UNAVAILABLE)

        def call() -> bytes:
            voice = self._piper()
            return _piper_wav(voice, spoken)

        try:
            data = self._tts.run(call)
        except SpeechProblem:
            raise
        except Exception:
            log.warning("speech synthesis failed: %s", "runtime")
            raise SpeechProblem(503, SYNTHESIS_UNAVAILABLE) from None

        if (
            not isinstance(data, bytes)
            or len(data) < 44
            or len(data) > MAX_WAV_BYTES
            or not data.startswith(b"RIFF")
            or data[8:12] != b"WAVE"
        ):
            raise SpeechProblem(503, SYNTHESIS_UNAVAILABLE)

        return data

    def _whisper(self):
        if self._model is not None:
            return self._model

        with self._load_lock:
            if self._model is None:
                self._model = _load_whisper()

        return self._model

    def _piper(self):
        if self._voice is not None:
            return self._voice

        with self._load_lock:
            if self._voice is None:
                self._voice = _load_piper()

        return self._voice


def _float32(samples: list[float]):
    import numpy as np

    clipped = [max(-1.0, min(1.0, sample)) for sample in samples]

    return np.asarray(clipped, dtype=np.float32)


def _load_whisper():
    try:
        from faster_whisper import WhisperModel
    except Exception:
        log.warning("speech transcription failed: %s", "import")
        raise SpeechProblem(503, TRANSCRIPTION_UNAVAILABLE) from None

    name = os.environ.get("SPEECH_STT_MODEL", "base.en")
    allow_download = os.environ.get("SPEECH_ALLOW_MODEL_DOWNLOAD", "").lower() in {
        "1",
        "true",
        "yes",
    }
    root = speech_home() / "whisper"
    root.mkdir(parents=True, exist_ok=True)

    try:
        return WhisperModel(
            name,
            device="cpu",
            compute_type="int8",
            download_root=str(root),
            local_files_only=not allow_download,
        )
    except Exception:
        log.warning("speech transcription failed: %s", "load")
        raise SpeechProblem(503, TRANSCRIPTION_UNAVAILABLE) from None


def _load_piper():
    path = _voice_path()

    if not path.is_file():
        log.warning("speech synthesis failed: %s", "missing-voice")
        raise SpeechProblem(503, SYNTHESIS_UNAVAILABLE) from None

    try:
        from piper import PiperVoice

        return PiperVoice.load(str(path))
    except Exception:
        log.warning("speech synthesis failed: %s", "load")
        raise SpeechProblem(503, SYNTHESIS_UNAVAILABLE) from None


def _piper_wav(voice, text: str) -> bytes:
    import io
    import wave

    buffer = io.BytesIO()

    with wave.open(buffer, "wb") as wav_file:
        if hasattr(voice, "synthesize_wav"):
            voice.synthesize_wav(text, wav_file)
        else:
            voice.synthesize(text, wav_file)

    return buffer.getvalue()


_runtime: SpeechRuntime | None = None
_runtime_lock = threading.Lock()


def get_runtime() -> SpeechRuntime:
    global _runtime

    if _runtime is None:
        with _runtime_lock:
            if _runtime is None:
                _runtime = LocalSpeechRuntime()

    return _runtime


def set_runtime(runtime: SpeechRuntime | None) -> None:
    """Test seam. Production calls never set this."""
    global _runtime

    _runtime = runtime
