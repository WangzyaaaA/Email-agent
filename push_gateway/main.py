from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import Engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from push_gateway.config import GatewaySettings, get_gateway_settings
from push_gateway.database import create_gateway_engine, create_session_factory, init_gateway_db, session_dependency
from push_gateway.fcm import FcmClient
from push_gateway.models import Device, GatewayCredential, GatewayMessage, RequestNonce, utcnow
from push_gateway.schemas import AckRequest, DeviceStatusRequest, MessageRequest, ProvisionRequest, RegisterRequest
from push_gateway.security import GatewayCipher, b64url_decode, bearer_token, new_token
from push_gateway.service import flush_gateway_messages, purge_gateway_data


logger = logging.getLogger(__name__)


class ApiFailure(Exception):
    def __init__(self, code: str, status_code: int = 400) -> None:
        self.code = code
        self.status_code = status_code


def error_response(code: str, status_code: int) -> JSONResponse:
    return JSONResponse({"error": {"code": code}}, status_code=status_code)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApiFailure("invalid_timestamp") from exc
    canonical = parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if canonical != value:
        raise ApiFailure("invalid_timestamp")
    return parsed.astimezone(timezone.utc)


def _canonical_device_request(request: Request, body: bytes, timestamp: str, nonce: str) -> bytes:
    try:
        b64url_decode(nonce, expected_length=16)
    except ValueError as exc:
        raise ApiFailure("invalid_signature_headers", 401) from exc
    if not timestamp.isdigit() or len(timestamp) != 10:
        raise ApiFailure("invalid_signature_headers", 401)
    target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    body_hash = hashlib.sha256(body).hexdigest()
    return f"v1\n{request.method.upper()}\n{target}\n{body_hash}\n{timestamp}\n{nonce}".encode("utf-8")


class RateLimiter:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._entries: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            entries = self._entries[key]
            while entries and entries[0] < now - 60:
                entries.popleft()
            if len(entries) >= self.limit:
                return False
            entries.append(now)
            return True


def create_app(
    settings: GatewaySettings | None = None,
    *,
    engine: Engine | None = None,
    fcm_client: FcmClient | None = None,
) -> FastAPI:
    selected = settings or get_gateway_settings()
    selected.ensure_data_dir()
    gateway_engine = engine or create_gateway_engine(selected)
    init_gateway_db(gateway_engine)
    factory = create_session_factory(gateway_engine)
    cipher = GatewayCipher(selected.master_key)
    fcm = fcm_client or FcmClient(selected)
    limiter = RateLimiter(selected.request_rate_per_minute)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        scheduler = BackgroundScheduler(timezone="UTC", daemon=True)
        scheduler.add_job(
            lambda: flush_gateway_messages(factory, selected, fcm),
            "interval",
            seconds=5,
            id="fcm-delivery",
            max_instances=1,
            coalesce=True,
        )
        scheduler.add_job(
            lambda: purge_gateway_data(factory, selected),
            "interval",
            minutes=5,
            id="gateway-cleanup",
            max_instances=1,
            coalesce=True,
        )
        scheduler.start()
        yield
        scheduler.shutdown(wait=False)

    app = FastAPI(
        title="Mail Sentinel Push Gateway",
        version="1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = selected
    app.state.session_factory = factory
    app.state.cipher = cipher
    get_db = session_dependency(factory)

    @app.exception_handler(ApiFailure)
    async def _api_failure(_request: Request, exc: ApiFailure):
        return error_response(exc.code, exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation_failure(_request: Request, _exc: RequestValidationError):
        return error_response("invalid_request", 422)

    @app.exception_handler(Exception)
    async def _unexpected_failure(_request: Request, _exc: Exception):
        logger.error("Push gateway request failed: type=%s", type(_exc).__name__)
        return error_response("internal_error", 500)

    @app.middleware("http")
    async def _boundary_checks(request: Request, call_next):  # type: ignore[no-untyped-def]
        forwarded_https = selected.trusted_proxy_headers and request.headers.get("x-forwarded-proto", "").lower() == "https"
        local_health = request.url.path == "/healthz" and request.client and request.client.host in {"127.0.0.1", "::1"}
        if request.url.scheme != "https" and not forwarded_https and not selected.allow_http_for_tests and not local_health:
            return error_response("https_required", 400)
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > selected.max_request_bytes:
            return error_response("request_too_large", 413)
        if request.method == "POST" and request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            return error_response("json_required", 415)
        source = request.client.host if request.client else "unknown"
        if selected.trusted_proxy_headers:
            forwarded_for = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
            if forwarded_for:
                source = forwarded_for
        if not limiter.allow(source):
            return error_response("rate_limited", 429)
        body = await request.body()
        if len(body) > selected.max_request_bytes:
            return error_response("request_too_large", 413)
        return await call_next(request)

    def require_scope(request: Request, db: Session, scope: str) -> None:
        try:
            token = bearer_token(request.headers.get("authorization"))
        except ValueError as exc:
            raise ApiFailure("authentication_required", 401) from exc
        fingerprint = cipher.fingerprint(token)
        credential = db.scalar(
            select(GatewayCredential).where(
                GatewayCredential.kind == scope,
                GatewayCredential.token_fingerprint == fingerprint,
                GatewayCredential.active.is_(True),
            )
        )
        if not credential:
            raise ApiFailure("invalid_credentials", 401)

    async def require_device(request: Request, db: Session, *, allow_pending: bool = False) -> Device:
        try:
            token = bearer_token(request.headers.get("authorization"))
        except ValueError as exc:
            raise ApiFailure("authentication_required", 401) from exc
        device = db.scalar(select(Device).where(Device.device_token_fingerprint == cipher.fingerprint(token)))
        if not device or not device.device_auth_key_encrypted:
            raise ApiFailure("invalid_device_credentials", 401)
        now = utcnow()
        if device.status == "pending_activation":
            if not device.activation_expires_at or _aware(device.activation_expires_at) <= now:
                device.status = "pairing_expired"
                device.device_token_fingerprint = None
                device.device_auth_key_encrypted = None
                db.commit()
                raise ApiFailure("pairing_expired", 401)
            # A provisioned device that has not uploaded an FCM registration yet is not a
            # revoked device. Keep the two apart so the app never deletes a fresh pairing.
            if not allow_pending:
                raise ApiFailure("device_not_activated", 409)
        elif device.status not in {"active", "waiting_registration"}:
            raise ApiFailure("invalid_device_credentials", 401)
        timestamp = request.headers.get("x-ms-timestamp", "")
        nonce = request.headers.get("x-ms-nonce", "")
        supplied = request.headers.get("x-ms-signature", "")
        canonical = _canonical_device_request(request, await request.body(), timestamp, nonce)
        if abs(int(timestamp) - int(now.timestamp())) > selected.max_clock_skew_seconds:
            raise ApiFailure("timestamp_out_of_window", 401)
        auth_key = b64url_decode(cipher.decrypt(device.device_auth_key_encrypted), expected_length=32)
        expected = hmac.new(auth_key, canonical, hashlib.sha256).digest()
        try:
            supplied_bytes = b64url_decode(supplied, expected_length=32)
        except ValueError as exc:
            raise ApiFailure("invalid_signature", 401) from exc
        if not hmac.compare_digest(expected, supplied_bytes):
            raise ApiFailure("invalid_signature", 401)
        nonce_fingerprint = cipher.fingerprint(nonce)
        try:
            with db.begin_nested():
                db.add(
                    RequestNonce(
                        device_id=device.id,
                        nonce_fingerprint=nonce_fingerprint,
                        expires_at=now + timedelta(seconds=selected.max_clock_skew_seconds),
                    )
                )
                db.flush()
        except IntegrityError as exc:
            raise ApiFailure("replay_detected", 409) from exc
        db.commit()
        return device

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/devices/provision")
    def provision_device(payload: ProvisionRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
        require_scope(request, db, "device_admin")
        now = utcnow()
        expires = _parse_utc(payload.activation_expires_at)
        if expires <= now or expires > now + timedelta(minutes=10, seconds=5):
            raise ApiFailure("invalid_activation_expiry")
        if db.scalar(select(Device).where(Device.status.in_(["pending_activation", "active", "waiting_registration"]))):
            raise ApiFailure("device_already_exists", 409)
        try:
            b64url_decode(payload.device_token, expected_length=32)
            b64url_decode(payload.device_auth_key, expected_length=32)
        except ValueError as exc:
            raise ApiFailure("invalid_device_material") from exc
        device = Device(
            device_id=payload.device_id,
            key_id=payload.key_id,
            status="pending_activation",
            device_token_fingerprint=cipher.fingerprint(payload.device_token),
            device_auth_key_encrypted=cipher.encrypt(payload.device_auth_key),
            activation_expires_at=expires,
        )
        db.add(device)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise ApiFailure("device_conflict", 409) from exc
        return {"device_id": device.device_id, "status": device.status}

    @app.get("/v1/devices/{device_id}/activation")
    def device_activation(device_id: str, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
        require_scope(request, db, "device_admin")
        device = db.scalar(select(Device).where(Device.device_id == device_id))
        if not device:
            raise ApiFailure("not_found", 404)
        if device.status == "pending_activation" and device.activation_expires_at and _aware(device.activation_expires_at) <= utcnow():
            device.status = "pairing_expired"
            device.device_token_fingerprint = None
            device.device_auth_key_encrypted = None
            db.commit()
        return {"device_id": device.device_id, "status": device.status}

    @app.post("/v1/devices/{device_id}/revoke")
    def revoke_device(device_id: str, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
        require_scope(request, db, "device_admin")
        device = db.scalar(select(Device).where(Device.device_id == device_id))
        if not device:
            raise ApiFailure("not_found", 404)
        device.status = "revoked"
        device.revoked_at = utcnow()
        device.device_token_fingerprint = None
        device.device_auth_key_encrypted = None
        device.fcm_token_encrypted = None
        messages = db.scalars(select(GatewayMessage).where(GatewayMessage.device_id == device.id)).all()
        for message in messages:
            message.status = "revoked"
            message.envelope_encrypted = None
            message.lease_until = None
        db.commit()
        return {"device_id": device.device_id, "status": "revoked"}

    @app.post("/v1/devices/register")
    async def register_device(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
        device = await require_device(request, db, allow_pending=True)
        if payload.device_id != device.device_id:
            raise ApiFailure("device_mismatch", 403)
        if payload.registration_version < device.registration_version:
            raise ApiFailure("stale_registration_version", 409)
        if payload.registration_version == device.registration_version and device.fcm_token_encrypted:
            # Equal versions are accepted only while the gateway holds no registration of
            # its own (for example after FCM reported the stored one as unregistered), so a
            # device whose FID never changed can recover. Older versions stay rejected and
            # replay protection continues to rely on the nonce and timestamp checks.
            raise ApiFailure("stale_registration_version", 409)
        device.fcm_token_encrypted = cipher.encrypt(payload.fcm_token)
        device.registration_version = payload.registration_version
        device.app_protocol_version = payload.app_protocol_version
        device.last_seen_at = utcnow()
        if device.status == "pending_activation":
            device.status = "active"
            device.activated_at = utcnow()
        elif device.status == "waiting_registration":
            device.status = "active"
        waiting = db.scalars(
            select(GatewayMessage).where(GatewayMessage.device_id == device.id, GatewayMessage.status == "waiting_registration")
        ).all()
        for message in waiting:
            message.status = "accepted"
            message.next_attempt_at = utcnow()
        db.commit()
        return {"device_id": device.device_id, "status": device.status, "registration_version": device.registration_version}

    @app.post("/v1/devices/status")
    async def update_device_status(payload: DeviceStatusRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
        device = await require_device(request, db)
        if payload.device_id != device.device_id:
            raise ApiFailure("device_mismatch", 403)
        device.notifications_enabled = payload.notifications_enabled
        device.otp_channel_enabled = payload.otp_channel_enabled
        device.important_channel_enabled = payload.important_channel_enabled
        device.digest_channel_enabled = payload.digest_channel_enabled
        device.app_protocol_version = payload.app_protocol_version
        device.last_seen_at = utcnow()
        db.commit()
        return {"status": "accepted"}

    @app.post("/v1/messages")
    def publish_message(payload: MessageRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
        require_scope(request, db, "publisher")
        envelope = payload.envelope.model_dump()
        device = db.scalar(select(Device).where(Device.device_id == payload.envelope.device_id))
        if not device or device.status != "active" or device.key_id != payload.envelope.key_id:
            raise ApiFailure("device_unavailable", 409)
        expires = _parse_utc(payload.envelope.expires_at)
        now = utcnow()
        if expires <= now or expires > now + timedelta(hours=48, minutes=1):
            raise ApiFailure("invalid_expiry")
        fcm_size = len(json.dumps({"message": {"data": envelope}}, separators=(",", ":")).encode("utf-8"))
        if fcm_size > 3500:
            raise ApiFailure("payload_too_large", 413)
        canonical = json.dumps(envelope, separators=(",", ":"), sort_keys=True)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        idempotency_fingerprint = cipher.fingerprint(payload.idempotency_key)
        existing = db.scalar(select(GatewayMessage).where(GatewayMessage.idempotency_fingerprint == idempotency_fingerprint))
        if existing:
            if existing.envelope_digest != digest or existing.device_id != device.id:
                raise ApiFailure("idempotency_conflict", 409)
            return {
                "gateway_message_id": existing.gateway_message_id,
                "status": existing.status,
                "accepted_at": _aware(existing.created_at).isoformat().replace("+00:00", "Z"),
            }
        row = GatewayMessage(
            gateway_message_id=new_token()[:22],
            device_id=device.id,
            message_id=payload.envelope.message_id,
            idempotency_fingerprint=idempotency_fingerprint,
            envelope_digest=digest,
            envelope_encrypted=cipher.encrypt_json(envelope),
            priority=payload.envelope.priority,
            expires_at=expires,
            status="accepted",
            next_attempt_at=now,
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise ApiFailure("idempotency_conflict", 409) from exc
        return {
            "gateway_message_id": row.gateway_message_id,
            "status": "accepted",
            "accepted_at": _aware(row.created_at).isoformat().replace("+00:00", "Z"),
        }

    @app.get("/v1/messages/status")
    def message_status(idempotency_key: str, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
        require_scope(request, db, "publisher")
        if len(idempotency_key) > 128:
            raise ApiFailure("invalid_idempotency_key")
        row = db.scalar(
            select(GatewayMessage).where(GatewayMessage.idempotency_fingerprint == cipher.fingerprint(idempotency_key))
        )
        if not row:
            return {"exists": False}
        return {
            "exists": True,
            "gateway_message_id": row.gateway_message_id,
            "status": row.status,
            "accepted_at": _aware(row.created_at).isoformat().replace("+00:00", "Z"),
        }

    @app.get("/v1/messages/pending")
    async def pending_messages(
        request: Request,
        cursor: str | None = None,
        limit: int = 50,
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        device = await require_device(request, db)
        if limit < 1 or limit > 50 or (cursor is not None and (len(cursor) > 128 or not cursor.replace("_", "").replace("-", "").isalnum())):
            raise ApiFailure("invalid_pagination")
        cursor_id = 0
        if cursor:
            cursor_row = db.scalar(
                select(GatewayMessage).where(
                    GatewayMessage.gateway_message_id == cursor,
                    GatewayMessage.device_id == device.id,
                )
            )
            if not cursor_row:
                raise ApiFailure("invalid_cursor")
            cursor_id = cursor_row.id
        now = utcnow()
        rows = db.scalars(
            select(GatewayMessage)
            .where(
                GatewayMessage.device_id == device.id,
                GatewayMessage.id > cursor_id,
                GatewayMessage.expires_at > now,
                GatewayMessage.envelope_encrypted.is_not(None),
                GatewayMessage.status.in_(["accepted", "retry_wait", "waiting_registration", "fcm_accepted"]),
            )
            .order_by(GatewayMessage.id)
            .limit(limit + 1)
        ).all()
        page = rows[:limit]
        items = [
            {"gateway_message_id": row.gateway_message_id, "envelope": cipher.decrypt_json(row.envelope_encrypted or "")}
            for row in page
        ]
        next_cursor = page[-1].gateway_message_id if len(rows) > limit and page else None
        return {"items": items, "next_cursor": next_cursor}

    @app.post("/v1/messages/{gateway_message_id}/ack")
    async def acknowledge_message(
        gateway_message_id: str,
        payload: AckRequest,
        request: Request,
        db: Session = Depends(get_db),
    ) -> dict[str, str]:
        device = await require_device(request, db)
        if payload.device_id != device.device_id:
            raise ApiFailure("device_mismatch", 403)
        row = db.scalar(
            select(GatewayMessage).where(
                GatewayMessage.gateway_message_id == gateway_message_id,
                GatewayMessage.device_id == device.id,
            )
        )
        if not row:
            raise ApiFailure("not_found", 404)
        if payload.result in {"shown", "stored_notifications_disabled", "expired"}:
            row.status = "acknowledged" if payload.result != "expired" else "expired"
            row.envelope_encrypted = None
            row.acknowledged_at = utcnow()
            row.last_error_code = None
        else:
            row.last_error_code = "decrypt_failed"
        device.last_seen_at = utcnow()
        db.commit()
        return {"status": row.status}

    return app
