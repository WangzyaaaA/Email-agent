from __future__ import annotations

import httpx
import pytest

from push_gateway.config import GatewaySettings
from push_gateway.fcm import FcmClient
from push_gateway import fcm as fcm_module


class TokenProvider:
    def __init__(self) -> None:
        self.refreshes = 0

    def token(self, *, force_refresh: bool = False) -> str:
        if force_refresh:
            self.refreshes += 1
            return "access-token-refreshed"
        return "access-token-initial"


def _client() -> tuple[FcmClient, TokenProvider]:
    settings = GatewaySettings(
        master_key="gateway-master-key-with-more-than-32-random-characters",
        database_url="sqlite:///:memory:",
        firebase_project_id="test-project",
    )
    provider = TokenProvider()
    return FcmClient(settings, provider), provider


def _response(status: int, payload: dict, headers: dict | None = None) -> httpx.Response:
    return httpx.Response(status, json=payload, headers=headers, request=httpx.Request("POST", "https://fcm.googleapis.com"))


@pytest.mark.parametrize(
    ("response", "code", "retryable", "invalid"),
    [
        (_response(400, {"error": {"status": "INVALID_ARGUMENT"}}), "fcm_invalid_argument", False, False),
        (_response(403, {"error": {"status": "PERMISSION_DENIED"}}), "fcm_permission_denied", False, False),
        (_response(404, {"error": {"status": "UNREGISTERED"}}), "fcm_token_unregistered", False, True),
        (_response(404, {"error": {"status": "NOT_FOUND"}}), "fcm_request_failed", False, False),
        (_response(429, {"error": {"status": "RESOURCE_EXHAUSTED"}}, {"Retry-After": "12"}), "fcm_quota_exceeded", True, False),
        (_response(500, {"error": {"status": "INTERNAL"}}), "fcm_service_unavailable", True, False),
        (_response(503, {"error": {"status": "UNAVAILABLE"}}), "fcm_service_unavailable", True, False),
    ],
)
def test_fcm_error_classification(monkeypatch, response, code, retryable, invalid) -> None:
    client, _ = _client()
    monkeypatch.setattr(fcm_module.httpx, "post", lambda *args, **kwargs: response)
    result = client.send(fcm_token="registration", envelope={"priority": "high", "ciphertext": "opaque"}, ttl_seconds=60)
    assert result.error_code == code
    assert result.retryable is retryable
    assert result.registration_invalid is invalid
    if response.status_code == 429:
        assert result.retry_after_seconds == 60


def test_fcm_network_timeout_is_retryable(monkeypatch) -> None:
    client, _ = _client()

    def timeout(*args, **kwargs):
        raise httpx.ReadTimeout("timeout", request=httpx.Request("POST", "https://fcm.googleapis.com"))

    monkeypatch.setattr(fcm_module.httpx, "post", timeout)
    result = client.send(fcm_token="registration", envelope={"priority": "normal"}, ttl_seconds=60)
    assert result.retryable and result.error_code == "fcm_transport_error"


def test_fcm_401_refreshes_once_then_accepts(monkeypatch) -> None:
    client, provider = _client()
    responses = iter(
        [
            _response(401, {"error": {"status": "UNAUTHENTICATED"}}),
            _response(200, {"name": "projects/test/messages/opaque"}),
        ]
    )
    monkeypatch.setattr(fcm_module.httpx, "post", lambda *args, **kwargs: next(responses))
    result = client.send(fcm_token="registration", envelope={"priority": "high"}, ttl_seconds=60)
    assert result.accepted and provider.refreshes == 1
