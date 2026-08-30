from __future__ import annotations

import ipaddress
import json
import secrets
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import httpx

from app.config import get_settings
from app.push_protocol import (
    b64url_decode,
    b64url_encode,
    derive_device_keys,
    encrypt_envelope,
    html_to_plain_text,
    new_opaque_id,
    notification_plaintext,
)


class GatewayFailure(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        retryable: bool = False,
        uncertain: bool = False,
        device_unavailable: bool = False,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.uncertain = uncertain
        self.device_unavailable = device_unavailable


def normalize_gateway_url(value: str, *, allow_loopback: bool | None = None) -> str:
    allow_test = get_settings().allow_loopback_gateway_for_tests if allow_loopback is None else allow_loopback
    parsed = urlsplit(value.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("网关地址必须是没有嵌入凭据的 HTTPS 地址")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("网关地址只能包含 HTTPS 源站，不能包含路径、查询或片段")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        address = None
    if not allow_test and (host == "localhost" or (address and (address.is_loopback or address.is_private or address.is_link_local))):
        raise ValueError("生产网关必须使用可公开验证证书的独立域名")
    if parsed.port not in {None, 443}:
        raise ValueError("生产网关只允许默认 HTTPS 端口 443")
    normalized_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return urlunsplit(("https", normalized_host, "", "", ""))


@dataclass(frozen=True)
class PairingMaterial:
    gateway_url: str
    device_id: str
    key_id: str
    device_token: str
    content_root_key: bytes
    expires_at: datetime

    def qr_payload(self) -> str:
        return json.dumps(
            {
                "version": 1,
                "gateway_url": self.gateway_url,
                "device_id": self.device_id,
                "key_id": self.key_id,
                "device_token": self.device_token,
                "content_root_key": b64url_encode(self.content_root_key),
                "expires_at": self.expires_at.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


def new_pairing_material(gateway_url: str, now: datetime) -> PairingMaterial:
    normalized = normalize_gateway_url(gateway_url)
    return PairingMaterial(
        gateway_url=normalized,
        device_id=new_opaque_id(),
        key_id=new_opaque_id(),
        device_token=b64url_encode(secrets.token_bytes(32)),
        content_root_key=secrets.token_bytes(32),
        expires_at=now + timedelta(minutes=10),
    )


class GatewayClient:
    """NAS-side client. Exceptions expose only stable error codes."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 10.0) -> None:
        self.base_url = normalize_gateway_url(base_url)
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, path: str, *, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            with httpx.Client(
                base_url=self.base_url,
                timeout=httpx.Timeout(self.timeout, connect=5.0),
                follow_redirects=False,
                headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
            ) as client:
                response = client.request(method, path, json=payload)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteError, socket.gaierror) as exc:
            raise GatewayFailure("gateway_unreachable", retryable=True, uncertain=method == "POST") from exc
        except httpx.TransportError as exc:
            code = "tls_validation_failed" if "certificate" in str(exc).lower() or "ssl" in str(exc).lower() else "gateway_transport_error"
            raise GatewayFailure(code, retryable=code != "tls_validation_failed", uncertain=method == "POST") from exc
        if 300 <= response.status_code < 400:
            raise GatewayFailure("redirect_rejected")
        data: dict[str, Any] = {}
        try:
            parsed = response.json()
            if isinstance(parsed, dict):
                data = parsed
        except ValueError:
            pass
        if 200 <= response.status_code < 300:
            return data
        remote_code = data.get("error", {}).get("code") if isinstance(data.get("error"), dict) else None
        safe_code = remote_code if remote_code in {
            "device_unavailable", "device_revoked", "idempotency_conflict", "not_found", "rate_limited"
        } else None
        if response.status_code in {401, 403}:
            raise GatewayFailure("gateway_authentication_failed")
        if response.status_code == 429:
            raise GatewayFailure("gateway_rate_limited", retryable=True)
        if response.status_code >= 500:
            raise GatewayFailure("gateway_server_error", retryable=True)
        if safe_code in {"device_unavailable"}:
            raise GatewayFailure(safe_code, retryable=True, device_unavailable=True)
        if response.status_code == 404:
            raise GatewayFailure(safe_code or "not_found")
        raise GatewayFailure(safe_code or "gateway_request_rejected")

    def provision(self, material: PairingMaterial) -> dict[str, Any]:
        _, auth_key = derive_device_keys(material.content_root_key, material.device_id)
        return self._request(
            "POST",
            "/v1/devices/provision",
            payload={
                "device_id": material.device_id,
                "key_id": material.key_id,
                "device_token": material.device_token,
                "device_auth_key": b64url_encode(auth_key),
                "activation_expires_at": material.expires_at.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            },
        )

    def activation(self, device_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/devices/{quote(device_id, safe='')}/activation")

    def revoke(self, device_id: str) -> dict[str, Any]:
        return self._request("POST", f"/v1/devices/{quote(device_id, safe='')}/revoke", payload={})

    def publish(self, idempotency_key: str, envelope: dict[str, str]) -> dict[str, Any]:
        return self._request(
            "POST",
            "/v1/messages",
            payload={"idempotency_key": idempotency_key, "envelope": envelope},
        )

    def status(self, idempotency_key: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/messages/status?idempotency_key={quote(idempotency_key, safe='')}")


def default_expiry(kind: str, priority: str, created_at: datetime) -> datetime:
    if kind == "otp":
        delta = timedelta(minutes=10)
    elif kind == "deadline" and priority == "critical":
        delta = timedelta(hours=2)
    elif kind == "digest":
        delta = timedelta(hours=48)
    else:
        delta = timedelta(hours=24)
    return created_at.astimezone(timezone.utc) + delta


def freeze_envelope(
    *,
    content_root_key: bytes,
    device_id: str,
    key_id: str,
    kind: str,
    priority: str,
    title: str,
    html_content: str,
    created_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    transport_priority = "high" if priority in {"high", "critical"} or kind in {"otp", "security"} else "normal"
    plaintext = notification_plaintext(
        kind=kind,
        title=title,
        body=html_to_plain_text(html_content),
        created_at=created_at,
    )
    envelope = encrypt_envelope(
        content_root_key=content_root_key,
        message_id=new_opaque_id(),
        device_id=device_id,
        key_id=key_id,
        priority=transport_priority,
        expires_at=expires_at,
        plaintext=plaintext,
    )
    return {"idempotency_key": new_opaque_id(), "envelope": envelope}


def decode_content_root_key(value: str) -> bytes:
    return b64url_decode(value, expected_length=32)
