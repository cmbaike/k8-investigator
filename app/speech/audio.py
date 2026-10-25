"""Bounded WAV decoding.

The browser records 16-bit PCM WAV. Decoding uses the standard library only,
so a recording cannot invoke a media toolkit or a shell. Bytes are not written
to disk.
"""

import io
import wave

from app.speech.problems import (
    EMPTY_AUDIO,
    INVALID_AUDIO,
    SpeechProblem,
    TOO_LONG,
)

MAX_AUDIO_BYTES = 6_000_000
MAX_AUDIO_SECONDS = 30.0
MIN_AUDIO_SECONDS = 0.3
TARGET_RATE = 16_000
ALLOWED_MEDIA_TYPES = frozenset(
    {"audio/wav", "audio/wave", "audio/x-wav", "audio/vnd.wave"}
)
# RMS below this is treated as silence (no model call).
_SILENCE_RMS = 0.008


def media_type(value: str | None) -> str:
    return (value or "").split(";", 1)[0].strip().lower()


def decode_wav(data: bytes) -> list[float]:
    """Mono float samples at 16 kHz, or a SpeechProblem the route can return."""
    if len(data) < 44 or not data.startswith(b"RIFF") or data[8:12] != b"WAVE":
        raise SpeechProblem(400, INVALID_AUDIO)

    try:
        with wave.open(io.BytesIO(data), "rb") as wav_file:
            channels = wav_file.getnchannels()
            width = wav_file.getsampwidth()
            rate = wav_file.getframerate()
            frames = wav_file.getnframes()

            if channels not in (1, 2) or width != 2 or not 8_000 <= rate <= 48_000:
                raise SpeechProblem(400, INVALID_AUDIO)

            if frames <= 0 or rate <= 0:
                raise SpeechProblem(400, EMPTY_AUDIO)

            duration = frames / rate

            if duration < MIN_AUDIO_SECONDS:
                raise SpeechProblem(400, EMPTY_AUDIO)

            if duration > MAX_AUDIO_SECONDS:
                raise SpeechProblem(400, TOO_LONG)

            raw = wav_file.readframes(frames)
    except SpeechProblem:
        raise
    except (wave.Error, EOFError):
        raise SpeechProblem(400, INVALID_AUDIO) from None

    if len(raw) != frames * channels * 2:
        raise SpeechProblem(400, INVALID_AUDIO)

    samples = _pcm16_to_float(raw, channels)

    if _rms(samples) < _SILENCE_RMS:
        raise SpeechProblem(400, EMPTY_AUDIO)

    return _resample(samples, rate, TARGET_RATE)


def _pcm16_to_float(raw: bytes, channels: int) -> list[float]:
    count = len(raw) // 2
    values = [int.from_bytes(raw[i * 2 : i * 2 + 2], "little", signed=True) / 32768.0 for i in range(count)]

    if channels == 1:
        return values

    mixed = []

    for index in range(0, len(values) - 1, 2):
        mixed.append((values[index] + values[index + 1]) / 2)

    return mixed


def _rms(samples: list[float]) -> float:
    if not samples:
        return 0.0

    return (sum(sample * sample for sample in samples) / len(samples)) ** 0.5


def _resample(samples: list[float], source_rate: int, target_rate: int) -> list[float]:
    if source_rate == target_rate or not samples:
        return samples

    duration = len(samples) / source_rate
    target_length = max(1, int(duration * target_rate))
    scaled: list[float] = []
    last = len(samples) - 1

    for index in range(target_length):
        position = index * source_rate / target_rate
        left = min(int(position), last)
        right = min(left + 1, last)
        weight = position - left
        scaled.append(samples[left] * (1 - weight) + samples[right] * weight)

    return scaled
