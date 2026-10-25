from fastapi import Depends

from app.security.api_keys import APIKeyPrincipal
from app.security.config import demo_principal


def get_demo_principal() -> APIKeyPrincipal:
    """The open demo identity. There is no credential to present."""

    return demo_principal()


def require_api_key_principal(
    principal: APIKeyPrincipal = Depends(get_demo_principal),
) -> APIKeyPrincipal:
    """Route dependency kept so handlers still receive a namespace scope.

    It does not read or require an API key.
    """

    return principal
