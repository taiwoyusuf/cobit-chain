from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx


@dataclass(frozen=True)
class OAuthConfig:
    tenant_id: str
    client_id: str
    redirect_uri: str
    scope: str

    @property
    def authorize_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize"

    @property
    def token_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"


def load_oauth_config() -> OAuthConfig:
    return OAuthConfig(
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_id=os.environ["AZURE_CLIENT_ID"],
        redirect_uri=os.environ["AZURE_REDIRECT_URI"],
        scope=os.environ["AZURE_MCP_SCOPE"],
    )


def create_pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).rstrip(b"=").decode("ascii")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def create_state() -> str:
    return secrets.token_urlsafe(32)


def build_authorization_url(config: OAuthConfig, *, state: str, challenge: str) -> str:
    query = urlencode(
        {
            "client_id": config.client_id,
            "response_type": "code",
            "redirect_uri": config.redirect_uri,
            "response_mode": "query",
            "scope": config.scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{config.authorize_url}?{query}"


async def exchange_code(config: OAuthConfig, *, code: str, verifier: str) -> dict:
    payload = {
        "client_id": config.client_id,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.redirect_uri,
        "code_verifier": verifier,
        "scope": config.scope,
    }
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(config.token_url, data=payload)
        response.raise_for_status()
        return response.json()
