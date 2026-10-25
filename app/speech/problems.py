"""Fixed failures for the speech endpoints.

`detail` is a constant the browser may show. It never includes audio,
transcript text, file paths, or an exception message.
"""


class SpeechProblem(Exception):
    def __init__(self, status: int, detail: str) -> None:
        self.status = status
        self.detail = detail
        super().__init__(detail)


UNSUPPORTED_TYPE = "That audio format is not supported."
TOO_LARGE = "The recording is too large."
INVALID_AUDIO = "The recording could not be read."
EMPTY_AUDIO = "The recording is empty."
TOO_LONG = "The recording is too long."
TRANSCRIPTION_UNAVAILABLE = "Speech transcription is unavailable."
TRANSCRIPTION_BUSY = "Speech transcription is busy. Try again in a moment."
TRANSCRIPTION_TIMEOUT = "Speech transcription took too long."
SYNTHESIS_UNAVAILABLE = "Speech synthesis is unavailable."
SYNTHESIS_BUSY = "Speech synthesis is busy. Try again in a moment."
SYNTHESIS_TIMEOUT = "Speech synthesis took too long."
