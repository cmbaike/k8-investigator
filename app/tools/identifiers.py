import re

from pydantic import BaseModel, ConfigDict

from app.tools.provenance import ArgumentSource, AssertionStatus


class TrustedIdentifier(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    value: str
    source: ArgumentSource
    evidence: str
    assertion: AssertionStatus


_IDENTIFIER_PATTERNS = {
   "namespace": re.compile(
       r"\b(?:in\s+)?namespace(?:\s+is)?\s+"
       r"(?P<value>[a-z0-9][a-z0-9.-]*)\b",
       re.IGNORECASE,
    ),
    "pod": re.compile(
        r"\bpod\s+(?P<value>[a-z0-9][a-z0-9.-]*)\b",
        re.IGNORECASE,
    ),
    "deployment": re.compile(
        r"\bdeployment\s+(?P<value>[a-z0-9][a-z0-9.-]*)\b",
        re.IGNORECASE,
    ),
    "container": re.compile(
        r"\bcontainer\s+(?P<value>[a-z0-9][a-z0-9.-]*)\b",
        re.IGNORECASE,
    ),
}


_UNTRUSTED_PREFIX = re.compile(
    r"\b(?:assume|guess|suppose|imagine|pretend)\b",
    re.IGNORECASE,
)


def extract_user_identifiers(
    user_text: str,
) -> list[TrustedIdentifier]:
    identifiers: list[TrustedIdentifier] = []

    for name, pattern in _IDENTIFIER_PATTERNS.items():
        for match in pattern.finditer(user_text):
            evidence = match.group(0)
            value = match.group("value")

            # Inspect only the nearby clause preceding the identifier.
            prefix_start = max(0, match.start() - 80)
            prefix = user_text[prefix_start:match.start()]

            assertion = (
                AssertionStatus.UNTRUSTED
                if _UNTRUSTED_PREFIX.search(prefix)
                else AssertionStatus.ASSERTED
            )

            identifiers.append(
                TrustedIdentifier(
                    name=name,
                    value=value,
                    source=ArgumentSource.USER,
                    evidence=evidence,
                    assertion=assertion,
                )
            )

    return identifiers

def find_asserted_user_identifier(
    identifiers: list[TrustedIdentifier],
    name: str,
    value: str,
) -> TrustedIdentifier | None:
    for identifier in identifiers:
        if (
            identifier.name == name
            and identifier.value == value
            and identifier.assertion == AssertionStatus.ASSERTED
        ):
            return identifier

    return None