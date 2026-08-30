from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from push_gateway.config import GatewaySettings


@dataclass(frozen=True)
class FcmResult:
    accepted: bool
    message_name: str | None = None
    error_code: str | None = None
    retryable: bool = False
    registration_invalid: bool = False
    retry_after_seconds: int | None = None


class GoogleAccessTokenProvider:
    """Caches official google-auth access tokens only in process memory."""

    def __init__(self, service_account_file: str) -> None:
        self.service_account_file = service_account_file
        self._lock = threading.Lock()
        self._credentials = None

    def token(self, *, force_refresh: bool = False) -> str:
        if not self.service_account_file or not Path(self.service_account_file).is_file():
            raise RuntimeError("firebase_credentials_unavailable")
        with self._lock:
            try:
                from google.auth.transport.requests import Request
                from google.oauth2 import service_account
            except ImportError as exc:
                raise RuntimeError("google_auth_dependency_missing") from exc
            if self._credentials is None:
                self._credentials = service_account.Credentials.from_service_account_file(
                    self.service_account_file,
                    scopes=["https://www.googleapis.com/auth/firebase.messaging"],
                )
            expires_soon = not self._credentials.expiry or self._credentials.expiry <= datetime.now(timezone.utc) + timedelta(minutes=5)
            if force_refresh or not self._credentials.token or expires_soon:
                self._credentials.refresh(Request())
            return str(self._credentials.token)


class FcmClient:
    def __init__(self, settings: GatewaySettings, token_provider: GoogleAccessTokenProvider | None = None) -> None:
        self.project_id = settings.firebase_project_id
        self.token_provider = token_provider or GoogleAccessTokenProvider(settings.firebase_service_account_file)
        self.endpoint = f"https://fcm.googleapis.com/v1/projects/{self.project_id}/messages:send"

    def send(self, *, fcm_token: str, envelope: dict[str, str], ttl_seconds: int) -> FcmResult:
        wire_size = len(json.dumps({"message": {"data": envelope}}, separators=(",", ":")).encode("utf-8"))
        if wire_size > 4096:
            return FcmResult(False, error_code="fcm_payload_too_large")
        try:
            access_token = self.token_provider.token()
        except RuntimeError as exc:
            return FcmResult(False, error_code=str(exc) if str(exc) in {"firebase_credentials_unavailable", "google_auth_dependency_missing"} else "fcm_oauth_failed")
        except Exception:
            return FcmResult(False, error_code="fcm_oauth_transport_error", retryable=True)
        payload = {
            "message": {
                "token": fcm_token,
                "data": envelope,
                "android": {
                    "priority": "HIGH" if envelope["priority"] == "high" else "NORMAL",
                    "ttl": f"{max(0, ttl_seconds)}s",
                },
            }
        }
        try:
            response = httpx.post(
                self.endpoint,
                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                json=payload,
                timeout=httpx.Timeout(15.0, connect=5.0),
                follow_redirects=False,
            )
        except httpx.TransportError:
            return FcmResult(False, error_code="fcm_transport_error", retryable=True)
        if 200 <= response.status_code < 300:
            try:
                name = response.json().get("name")
            except ValueError:
                name = None
            return FcmResult(bool(name), message_name=name if isinstance(name, str) else None, error_code=None if name else "fcm_invalid_response")
        parsed: dict[str, Any] = {}
        try:
            body = response.json()
            if isinstance(body, dict):
                parsed = body
        except ValueError:
            pass
        error = parsed.get("error") if isinstance(parsed.get("error"), dict) else {}
        status = str(error.get("status", ""))
        details = error.get("details") if isinstance(error.get("details"), list) else []
        detail_codes = {
            str(item.get("errorCode", ""))
            for item in details
            if isinstance(item, dict)
        }
        unregistered = status == "UNREGISTERED" or "UNREGISTERED" in detail_codes
        if unregistered:
            return FcmResult(False, error_code="fcm_token_unregistered", registration_invalid=True)
        if response.status_code == 401:
            try:
                refreshed = self.token_provider.token(force_refresh=True)
            except Exception:
                return FcmResult(False, error_code="fcm_oauth_failed")
            if refreshed != access_token:
                return self._send_after_refresh(fcm_token=fcm_token, envelope=envelope, ttl_seconds=ttl_seconds, token=refreshed)
            return FcmResult(False, error_code="fcm_oauth_failed")
        if response.status_code == 403:
            return FcmResult(False, error_code="fcm_permission_denied")
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                seconds = int(retry_after)
            elif retry_after:
                try:
                    seconds = max(60, int((parsedate_to_datetime(retry_after) - datetime.now(timezone.utc)).total_seconds()))
                except (TypeError, ValueError, OverflowError):
                    seconds = 60
            else:
                seconds = 60
            return FcmResult(False, error_code="fcm_quota_exceeded", retryable=True, retry_after_seconds=max(60, seconds))
        if response.status_code in {500, 503}:
            return FcmResult(False, error_code="fcm_service_unavailable", retryable=True, retry_after_seconds=10)
        if response.status_code == 400:
            return FcmResult(False, error_code="fcm_invalid_argument")
        return FcmResult(False, error_code="fcm_request_failed", retryable=response.status_code >= 500)

    def _send_after_refresh(self, *, fcm_token: str, envelope: dict[str, str], ttl_seconds: int, token: str) -> FcmResult:
        payload = {
            "message": {
                "token": fcm_token,
                "data": envelope,
                "android": {
                    "priority": "HIGH" if envelope["priority"] == "high" else "NORMAL",
                    "ttl": f"{max(0, ttl_seconds)}s",
                },
            }
        }
        try:
            response = httpx.post(
                self.endpoint,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=payload,
                timeout=httpx.Timeout(15.0, connect=5.0),
                follow_redirects=False,
            )
        except httpx.TransportError:
            return FcmResult(False, error_code="fcm_transport_error", retryable=True)
        if 200 <= response.status_code < 300:
            try:
                name = response.json().get("name")
            except ValueError:
                name = None
            return FcmResult(bool(name), message_name=name if isinstance(name, str) else None, error_code=None if name else "fcm_invalid_response")
        try:
            parsed = response.json()
        except ValueError:
            parsed = {}
        error = parsed.get("error") if isinstance(parsed, dict) and isinstance(parsed.get("error"), dict) else {}
        status = str(error.get("status", ""))
        details = error.get("details") if isinstance(error.get("details"), list) else []
        detail_codes = {str(item.get("errorCode", "")) for item in details if isinstance(item, dict)}
        if status == "UNREGISTERED" or "UNREGISTERED" in detail_codes:
            return FcmResult(False, error_code="fcm_token_unregistered", registration_invalid=True)
        if response.status_code == 403:
            return FcmResult(False, error_code="fcm_permission_denied")
        if response.status_code == 429:
            return FcmResult(False, error_code="fcm_quota_exceeded", retryable=True, retry_after_seconds=60)
        if response.status_code in {500, 503}:
            return FcmResult(False, error_code="fcm_service_unavailable", retryable=True, retry_after_seconds=10)
        return FcmResult(False, error_code="fcm_oauth_failed")
