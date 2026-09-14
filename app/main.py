from __future__ import annotations

import hashlib
import base64
import io
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app import __version__
from app.config import get_settings
from app.database import SessionLocal, get_db, init_db
from app.mail.imap_source import test_connection
from app.mail.providers import detect_provider, preset_endpoint
from app.models import (
    ActionItem,
    ActionStatus,
    AuditEvent,
    DigestRun,
    MailboxAccount,
    MessageMetadata,
    Notification,
    NotificationStatus,
    OtpCandidate,
    PushDevice,
    Rule,
    utcnow,
)
from app.scheduler import build_scheduler
from app.security import Cipher, hash_password, new_csrf_token, verify_password
from app.services.digests import build_digest, due_digest_types
from app.services.classifier import normalize_model_url
from app.services.monitor import monitor_manager
from app.services.notifier import enqueue_test_notification, flush_notifications, pause_notification_delivery
from app.push_protocol import b64url_decode, b64url_encode
from app.services.fcm_channel import GatewayClient, GatewayFailure, new_pairing_material, normalize_gateway_url
from app.services.push_management import finish_local_revocation, invalidate_revoked_device_envelopes
from app.store import audit, get_setting, has_admin, set_setting


settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if not settings.production_key_configured:
        raise RuntimeError(
            "Refusing to start with the development master key. Set EMAIL_AGENT_MASTER_KEY to at least 32 random characters."
        )
    init_db()
    scheduler = build_scheduler()
    scheduler.start()
    monitor_manager.refresh()
    yield
    scheduler.shutdown(wait=False)
    monitor_manager.stop_all()


app = FastAPI(title="邮箱智能 Agent", version=__version__, docs_url=None, redoc_url=None, lifespan=lifespan)
session_secret = hashlib.sha256(("session:" + settings.master_key).encode()).hexdigest()
app.add_middleware(
    SessionMiddleware,
    secret_key=session_secret,
    same_site="lax",
    https_only=settings.secure_cookies,
    max_age=60 * 60 * 12,
)
base_dir = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(base_dir / "templates"))
app.mount("/static", StaticFiles(directory=str(base_dir / "static"), check_dir=False), name="static")


def _csrf(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = new_csrf_token()
        request.session["csrf_token"] = token
    return token


def _verify_csrf(request: Request, token: str) -> None:
    expected = request.session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(expected, token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token invalid")


def _authenticated(request: Request) -> bool:
    return request.session.get("admin") is True


def require_admin(request: Request) -> None:
    if not _authenticated(request):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="请先登录")


def page_context(request: Request, **values):  # type: ignore[no-untyped-def]
    return {
        "request": request,
        "csrf_token": _csrf(request),
        "authenticated": _authenticated(request),
        "current_user": "管理员" if _authenticated(request) else None,
        "version": __version__,
        "security_warning": not settings.production_key_configured,
        **values,
    }


def render(request: Request, name: str, status_code: int = 200, **values) -> HTMLResponse:  # type: ignore[no-untyped-def]
    return templates.TemplateResponse(request=request, name=name, context=page_context(request, **values), status_code=status_code)


@app.exception_handler(401)
async def unauthorized_handler(request: Request, _exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/api/health")
def api_health(request: Request, db: Session = Depends(get_db)) -> dict:
    require_admin(request)
    counts = dict(db.execute(select(MailboxAccount.status, func.count()).group_by(MailboxAccount.status)).all())
    return {"status": "ok", "mailboxes": counts, "time": utcnow().isoformat()}


def _is_overdue(value) -> bool:  # type: ignore[no-untyped-def]
    if value is None:
        return False
    if value.tzinfo is None:
        return value < utcnow().replace(tzinfo=None)
    return value < utcnow()


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    if not has_admin(db):
        return RedirectResponse("/setup", status_code=303)
    if not _authenticated(request):
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, db: Session = Depends(get_db)):
    if has_admin(db):
        return RedirectResponse("/login", status_code=303)
    return render(request, "setup.html")


@app.post("/setup", response_class=HTMLResponse, name="setup_post")
def setup_submit(
    request: Request,
    admin_password: str = Form(...),
    admin_password_confirm: str = Form(...),
    wxpusher_app_token: str = Form(""),
    wxpusher_uid: str = Form(""),
    llm_base_url: str = Form(""),
    llm_api_key: str = Form(""),
    llm_model: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _verify_csrf(request, csrf_token)
    if has_admin(db):
        return RedirectResponse("/login", status_code=303)
    if admin_password != admin_password_confirm or len(admin_password) < 12:
        return render(request, "setup.html", status_code=400, error="管理员密码至少 12 位，且两次输入必须一致")
    if llm_base_url.strip():
        try:
            llm_base_url = normalize_model_url(llm_base_url)
        except ValueError as exc:
            return render(request, "setup.html", status_code=400, error=str(exc))
    set_setting(db, "admin_password_hash", hash_password(admin_password))
    for key, value in {
        "wxpusher_app_token": wxpusher_app_token,
        "wxpusher_uid": wxpusher_uid,
        "llm_base_url": llm_base_url,
        "llm_api_key": llm_api_key,
        "llm_model": llm_model,
    }.items():
        if value.strip():
            set_setting(db, key, value.strip())
    audit(db, "setup_complete", "Initial administrator configured")
    db.commit()
    request.session["admin"] = True
    request.session["csrf_token"] = new_csrf_token()
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if not has_admin(db):
        return RedirectResponse("/setup", status_code=303)
    if _authenticated(request):
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "login.html")


@app.post("/login", response_class=HTMLResponse, name="login_post")
def login_submit(
    request: Request,
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    _verify_csrf(request, csrf_token)
    encoded = get_setting(db, "admin_password_hash") or ""
    if not verify_password(encoded, password):
        audit(db, "login_failed", "Administrator login failed")
        db.commit()
        return render(request, "login.html", status_code=400, error="密码错误")
    request.session.clear()
    request.session["admin"] = True
    request.session["csrf_token"] = new_csrf_token()
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    counts = {
        "mailboxes": db.scalar(select(func.count()).select_from(MailboxAccount)) or 0,
        "messages": db.scalar(select(func.count()).select_from(MessageMetadata)) or 0,
        "actions": db.scalar(select(func.count()).select_from(ActionItem).where(ActionItem.status != ActionStatus.DONE.value)) or 0,
        "otp_candidates": db.scalar(select(func.count()).select_from(OtpCandidate).where(OtpCandidate.status == "pending")) or 0,
        "failed_notifications": db.scalar(select(func.count()).select_from(Notification).where(Notification.status == NotificationStatus.FAILED.value)) or 0,
    }
    mailboxes = db.scalars(select(MailboxAccount).order_by(MailboxAccount.created_at)).all()
    recent = db.scalars(select(MessageMetadata).order_by(MessageMetadata.received_at.desc()).limit(10)).all()
    pending_actions = db.scalars(
        select(ActionItem).where(ActionItem.status != ActionStatus.DONE.value).order_by(ActionItem.due_at.asc()).limit(6)
    ).all()
    healthy = sum(1 for mailbox in mailboxes if mailbox.status in {"healthy", "connected"})
    stats = {
        "new_messages": counts["messages"],
        "pending_actions": counts["actions"],
        "overdue_actions": sum(1 for item in pending_actions if _is_overdue(item.due_at)),
        "pending_otps": counts["otp_candidates"],
        "otp_sent": db.scalar(select(func.count()).select_from(Notification).where(Notification.kind == "otp", Notification.status == "sent")) or 0,
        "healthy_mailboxes": healthy,
        "total_mailboxes": len(mailboxes),
    }
    return render(
        request,
        "dashboard.html",
        stats=stats,
        counts=counts,
        mailboxes=mailboxes,
        sync_status=mailboxes,
        pending_actions=pending_actions,
        recent_messages=recent,
        active_nav="dashboard",
    )


@app.get("/mailboxes", response_class=HTMLResponse, name="mailboxes")
def mailboxes_page(request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    rows = db.scalars(select(MailboxAccount).order_by(MailboxAccount.created_at)).all()
    return render(request, "mailboxes.html", mailboxes=rows, active_nav="mailboxes")


@app.get("/mailboxes/new", response_class=HTMLResponse, name="mailbox_new")
def mailbox_new(request: Request):
    require_admin(request)
    return render(request, "mailbox_form.html", mailbox=None, active_nav="mailboxes")


@app.post("/mailboxes/new/detect", response_class=HTMLResponse, name="mailbox_detect_form")
def mailbox_detect_form(
    request: Request,
    email_address: str = Form(...),
    csrf_token: str = Form(...),
):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    try:
        result = detect_provider(email_address)
    except ValueError as exc:
        return render(request, "mailbox_form.html", mailbox=None, error=str(exc), active_nav="mailboxes", status_code=400)
    suggested = {
        "name": email_address,
        "email_address": email_address,
        "username": email_address,
        "provider": result.provider,
        "imap_host": result.host,
        "imap_port": result.port,
    }
    return render(
        request,
        "mailbox_form.html",
        mailbox=suggested,
        provider=result.provider,
        detected_provider="；".join(result.evidence),
        detection=result,
        active_nav="mailboxes",
    )


@app.post("/mailboxes/detect", response_class=HTMLResponse)
def mailbox_detect_page(
    request: Request,
    email_address: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    rows = db.scalars(select(MailboxAccount).order_by(MailboxAccount.created_at)).all()
    try:
        result = detect_provider(email_address)
        return render(request, "mailboxes.html", mailboxes=rows, detection=result, detected_email=email_address)
    except ValueError as exc:
        return render(request, "mailboxes.html", mailboxes=rows, error=str(exc), status_code=400)


@app.post("/api/mailboxes/detect")
def mailbox_detect_api(request: Request, payload: dict):
    require_admin(request)
    _verify_csrf(request, request.headers.get("X-CSRF-Token", ""))
    result = detect_provider(str(payload.get("email_address", "")))
    return {
        "provider": result.provider,
        "host": result.host,
        "port": result.port,
        "confidence": result.confidence,
        "evidence": result.evidence,
        "requires_confirmation": True,
    }


@app.post("/mailboxes", response_class=HTMLResponse, name="mailbox_create")
def mailbox_add(
    request: Request,
    name: str = Form(...),
    email_address: str = Form(...),
    provider: str = Form(...),
    imap_host: str = Form(...),
    imap_port: int = Form(993),
    username: str = Form(...),
    password: str = Form(...),
    host_confirmed: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    rows = db.scalars(select(MailboxAccount).order_by(MailboxAccount.created_at)).all()
    try:
        normalized_email = str(TypeAdapter(EmailStr).validate_python(email_address))
    except ValidationError:
        return render(request, "mailboxes.html", mailboxes=rows, error="邮箱地址格式不正确", status_code=400)
    if host_confirmed != "yes":
        return render(request, "mailboxes.html", mailboxes=rows, error="必须确认服务器地址后才能提交凭据", status_code=400)
    if imap_port != 993:
        return render(request, "mailboxes.html", mailboxes=rows, error="首版只允许 TLS IMAP 993 端口", status_code=400)
    known = {"qq", "gmail", "alibaba", "custom"}
    if provider not in known:
        return render(request, "mailboxes.html", mailboxes=rows, error="未知邮箱类型", status_code=400)
    endpoint = preset_endpoint(provider)
    if endpoint and imap_host.lower() != endpoint[0]:
        provider = "custom"
    connection = test_connection(imap_host.strip().lower(), imap_port, username.strip(), password, provider)
    account = MailboxAccount(
        name=name.strip()[:120],
        email_address=normalized_email.lower(),
        provider=provider,
        detected_provider=provider,
        imap_host=imap_host.strip().lower(),
        imap_port=imap_port,
        username=username.strip(),
        password_encrypted=Cipher().encrypt(password),
        host_confirmed=True,
        enabled=connection.ok,
        status="connected" if connection.ok else "error",
        last_error_code=None if connection.ok else connection.code,
        last_error=None if connection.ok else connection.message,
        capabilities=",".join(connection.capabilities),
    )
    db.add(account)
    try:
        audit(db, "mailbox_added", f"provider={provider} address={normalized_email.lower()}")
        db.commit()
    except Exception:
        db.rollback()
        return render(request, "mailboxes.html", mailboxes=rows, error="该邮箱已存在或配置无法保存", status_code=400)
    monitor_manager.refresh()
    return RedirectResponse("/mailboxes", status_code=303)


@app.get("/mailboxes/{mailbox_id}/edit", response_class=HTMLResponse, name="mailbox_edit")
def mailbox_edit(mailbox_id: int, request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    account = db.get(MailboxAccount, mailbox_id)
    if not account:
        raise HTTPException(404, "邮箱不存在")
    return render(request, "mailbox_form.html", mailbox=account, active_nav="mailboxes")


@app.post("/mailboxes/{mailbox_id}/edit", response_class=HTMLResponse, name="mailbox_update")
def mailbox_update(
    mailbox_id: int,
    request: Request,
    name: str = Form(...),
    email_address: str = Form(...),
    provider: str = Form(...),
    imap_host: str = Form(...),
    imap_port: int = Form(993),
    username: str = Form(...),
    password: str = Form(""),
    host_confirmed: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    account = db.get(MailboxAccount, mailbox_id)
    if not account:
        raise HTTPException(404, "邮箱不存在")
    if host_confirmed != "yes" or imap_port != 993:
        return render(request, "mailbox_form.html", mailbox=account, error="必须确认 TLS 993 服务器地址", active_nav="mailboxes", status_code=400)
    try:
        normalized_email = str(TypeAdapter(EmailStr).validate_python(email_address)).lower()
    except ValidationError:
        return render(request, "mailbox_form.html", mailbox=account, error="邮箱地址格式不正确", active_nav="mailboxes", status_code=400)
    selected_password = password or Cipher().decrypt(account.password_encrypted)
    result = test_connection(imap_host.strip().lower(), imap_port, username.strip(), selected_password, provider)
    account.name = name.strip()[:120]
    account.email_address = normalized_email
    account.provider = provider if provider in {"qq", "gmail", "alibaba", "custom"} else "custom"
    account.imap_host = imap_host.strip().lower()
    account.imap_port = imap_port
    account.username = username.strip()
    if password:
        account.password_encrypted = Cipher().encrypt(password)
    account.host_confirmed = True
    account.status = "connected" if result.ok else "error"
    account.enabled = result.ok
    account.last_error_code = None if result.ok else result.code
    account.last_error = None if result.ok else result.message
    account.capabilities = ",".join(result.capabilities)
    audit(db, "mailbox_updated", f"account={account.id} provider={account.provider}")
    db.commit()
    monitor_manager.refresh()
    return RedirectResponse("/mailboxes", status_code=303)


@app.post("/mailboxes/{mailbox_id}/test", name="mailbox_test")
def mailbox_test(mailbox_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    account = db.get(MailboxAccount, mailbox_id)
    if not account:
        raise HTTPException(404, "邮箱不存在")
    result = test_connection(account.imap_host, account.imap_port, account.username, Cipher().decrypt(account.password_encrypted), account.provider)
    account.status = "connected" if result.ok else "error"
    account.enabled = result.ok
    account.last_error_code = None if result.ok else result.code
    account.last_error = None if result.ok else result.message
    account.capabilities = ",".join(result.capabilities)
    audit(db, "mailbox_test", f"account={account.id} code={result.code}")
    db.commit()
    monitor_manager.refresh()
    return RedirectResponse("/mailboxes", status_code=303)


@app.post("/mailboxes/{mailbox_id}/sync", name="mailbox_sync")
def mailbox_sync(mailbox_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    account = db.get(MailboxAccount, mailbox_id)
    if not account:
        raise HTTPException(404, "邮箱不存在")
    account.status = "pending"
    db.commit()
    monitor_manager.request_sync(account.id)
    return RedirectResponse("/mailboxes", status_code=303)


@app.post("/mailboxes/{account_id}/toggle", name="mailbox_toggle")
def mailbox_toggle(account_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    account = db.get(MailboxAccount, account_id)
    if not account:
        raise HTTPException(404, "邮箱不存在")
    account.enabled = not account.enabled
    audit(db, "mailbox_toggled", f"account={account.id} enabled={account.enabled}")
    db.commit()
    monitor_manager.refresh()
    return RedirectResponse("/mailboxes", status_code=303)


@app.get("/rules", response_class=HTMLResponse, name="rules")
def rules_page(request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    rules = db.scalars(select(Rule).order_by(Rule.kind, Rule.value)).all()
    return render(request, "rules.html", rules=rules, active_nav="rules")


@app.post("/rules", name="rule_create")
def rule_add(
    request: Request,
    kind: str = Form(...),
    value: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    allowed = {"otp_address", "otp_domain", "vip_address", "vip_domain"}
    if kind not in allowed or not value.strip():
        raise HTTPException(400, "规则格式不正确")
    normalized = value.strip().lower().lstrip("@") if kind.endswith("domain") else value.strip().lower()
    existing = db.scalar(select(Rule).where(Rule.kind == kind, Rule.value == normalized))
    if existing:
        existing.enabled = True
    else:
        db.add(Rule(kind=kind, value=normalized))
    audit(db, "rule_saved", f"kind={kind} value={normalized}")
    db.commit()
    return RedirectResponse("/rules", status_code=303)


@app.post("/rules/{rule_id}/toggle", name="rule_toggle")
def rule_toggle(rule_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    row = db.get(Rule, rule_id)
    if not row:
        raise HTTPException(404, "规则不存在")
    row.enabled = not row.enabled
    audit(db, "rule_toggled", f"rule={row.id} enabled={row.enabled}")
    db.commit()
    return RedirectResponse("/rules", status_code=303)


@app.post("/rules/{rule_id}/delete", name="rule_delete")
def rule_delete(rule_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    row = db.get(Rule, rule_id)
    if not row:
        raise HTTPException(404, "规则不存在")
    audit(db, "rule_deleted", f"rule={row.id} kind={row.kind}")
    db.delete(row)
    db.commit()
    return RedirectResponse("/rules", status_code=303)


@app.get("/otp-candidates", response_class=HTMLResponse, name="otp_candidates")
def otp_candidates_page(request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    rows = db.scalars(select(OtpCandidate).order_by(OtpCandidate.created_at.desc()).limit(200)).all()
    return render(request, "otp_candidates.html", candidates=rows, active_nav="otp")


@app.post("/otp-candidates/{candidate_id}/approve", name="otp_approve")
def otp_candidate_approve(
    candidate_id: int,
    request: Request,
    scope: str = Form("address"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    row = db.get(OtpCandidate, candidate_id)
    if not row:
        raise HTTPException(404, "候选不存在")
    if row.risk == "authentication_failed":
        raise HTTPException(400, "认证失败的来源不能加入白名单")
    kind = "otp_domain" if scope == "domain" else "otp_address"
    value = row.sender_domain if scope == "domain" else row.sender_address
    existing = db.scalar(select(Rule).where(Rule.kind == kind, Rule.value == value))
    if not existing:
        db.add(Rule(kind=kind, value=value))
    row.status = "approved"
    audit(db, "otp_source_approved", f"kind={kind} value={value}")
    db.commit()
    return RedirectResponse("/otp-candidates", status_code=303)


@app.post("/otp-candidates/{candidate_id}/block", name="otp_reject")
def otp_candidate_block(candidate_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    row = db.get(OtpCandidate, candidate_id)
    if not row:
        raise HTTPException(404, "候选不存在")
    row.status = "blocked"
    audit(db, "otp_source_blocked", f"candidate={row.id}")
    db.commit()
    return RedirectResponse("/otp-candidates", status_code=303)


@app.get("/actions", response_class=HTMLResponse, name="actions")
def actions_page(request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    rows = db.scalars(select(ActionItem).order_by(ActionItem.status, ActionItem.due_at.asc())).all()
    return render(request, "actions.html", actions=rows, statuses=[item.value for item in ActionStatus], active_nav="actions")


@app.post("/actions/{action_id}/status", name="action_update")
def action_status(
    action_id: int,
    request: Request,
    new_status: str = Form(..., alias="status"),
    snooze_hours: int = Form(0),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    if new_status not in {item.value for item in ActionStatus}:
        raise HTTPException(400, "未知状态")
    row = db.get(ActionItem, action_id)
    if not row:
        raise HTTPException(404, "事项不存在")
    row.status = new_status
    row.snoozed_until = utcnow() + timedelta(hours=max(1, min(snooze_hours, 720))) if new_status == "snoozed" else None
    audit(db, "action_updated", f"action={row.id} status={new_status}")
    db.commit()
    return RedirectResponse("/actions", status_code=303)


@app.get("/notifications", response_class=HTMLResponse, name="notifications")
def notifications_page(request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    rows = db.scalars(select(Notification).order_by(Notification.created_at.desc()).limit(300)).all()
    return render(request, "notifications.html", notifications=rows, active_nav="notifications")


def _push_view(db: Session) -> dict:
    device = db.scalar(select(PushDevice).order_by(PushDevice.created_at.desc()))
    configured = {
        "gateway_url": get_setting(db, "fcm_gateway_url", "") or "",
        "publisher": bool(get_setting(db, "fcm_publisher_token")),
        "device_admin": bool(get_setting(db, "fcm_device_admin_token")),
    }
    return {
        "device": device,
        "configured": configured,
        "notification_channel": get_setting(db, "notification_channel", "wxpusher") or "wxpusher",
        "wxpusher_configured": bool(get_setting(db, "wxpusher_app_token") and get_setting(db, "wxpusher_uid")),
    }


@app.get("/push", response_class=HTMLResponse, name="push_settings")
def push_settings_page(request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    return render(request, "push.html", active_nav="push", **_push_view(db))


@app.post("/push/configure", name="push_configure")
def push_configure(
    request: Request,
    gateway_url: str = Form(...),
    publisher_token: str = Form(""),
    device_admin_token: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    try:
        normalized = normalize_gateway_url(gateway_url)
        if publisher_token.strip():
            b64url_decode(publisher_token.strip(), expected_length=32)
        if device_admin_token.strip():
            b64url_decode(device_admin_token.strip(), expected_length=32)
    except ValueError as exc:
        return render(request, "push.html", status_code=400, error=str(exc), active_nav="push", **_push_view(db))
    existing = db.scalar(
        select(PushDevice).where(PushDevice.status.in_(["pending_activation", "active", "revocation_pending"]))
    )
    if existing and existing.gateway_url != normalized:
        return render(
            request,
            "push.html",
            status_code=400,
            error="更换网关前必须先完成现有设备吊销。",
            active_nav="push",
            **_push_view(db),
        )
    set_setting(db, "fcm_gateway_url", normalized)
    if publisher_token.strip():
        set_setting(db, "fcm_publisher_token", publisher_token.strip())
    if device_admin_token.strip():
        set_setting(db, "fcm_device_admin_token", device_admin_token.strip())
    audit(db, "push_gateway_configured", "FCM gateway endpoint and scoped credentials updated")
    db.commit()
    return RedirectResponse("/push", status_code=303)


@app.post("/push/pair", response_class=HTMLResponse, name="push_pair")
def push_pair(
    request: Request,
    admin_password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    if not verify_password(get_setting(db, "admin_password_hash") or "", admin_password):
        return render(request, "push.html", status_code=400, error="管理员密码错误。", active_nav="push", **_push_view(db))
    view = _push_view(db)
    gateway_url = view["configured"]["gateway_url"]
    admin_token = get_setting(db, "fcm_device_admin_token")
    if not gateway_url or not admin_token or not view["configured"]["publisher"]:
        return render(request, "push.html", status_code=400, error="请先完整配置网关和两类 NAS 凭据。", active_nav="push", **view)
    existing = db.scalar(select(PushDevice).where(PushDevice.status.in_(["pending_activation", "active", "revocation_pending"])))
    if existing:
        return render(request, "push.html", status_code=409, error="已有待激活或使用中的设备，请先完成激活或吊销。", active_nav="push", **view)
    try:
        material = new_pairing_material(gateway_url, utcnow())
        GatewayClient(gateway_url, admin_token).provision(material)
    except (GatewayFailure, ValueError) as exc:
        code = exc.code if isinstance(exc, GatewayFailure) else "invalid_gateway_configuration"
        return render(request, "push.html", status_code=502, error=f"网关预配失败：{code}", active_nav="push", **view)
    db.add(
        PushDevice(
            device_id=material.device_id,
            key_id=material.key_id,
            gateway_url=material.gateway_url,
            content_root_key_encrypted=Cipher().encrypt(b64url_encode(material.content_root_key)),
            pending_device_token_encrypted=Cipher().encrypt(material.device_token),
            status="pending_activation",
            pairing_expires_at=material.expires_at,
        )
    )
    audit(db, "push_pairing_created", f"device={material.device_id}")
    db.commit()
    try:
        import qrcode

        image = qrcode.make(material.qr_payload())
        output = io.BytesIO()
        image.save(output, format="PNG")
        qr_data_uri = "data:image/png;base64," + base64.b64encode(output.getvalue()).decode("ascii")
    except ImportError:
        raise HTTPException(500, "二维码组件未安装")
    response = render(
        request,
        "push.html",
        active_nav="push",
        pairing_payload=material.qr_payload(),
        pairing_qr=qr_data_uri,
        pairing_expires_at=material.expires_at,
        **_push_view(db),
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; form-action 'self'; frame-ancestors 'none'"
    return response


@app.post("/push/check-activation", name="push_check_activation")
def push_check_activation(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    device = db.scalar(select(PushDevice).where(PushDevice.status == "pending_activation").order_by(PushDevice.created_at.desc()))
    token = get_setting(db, "fcm_device_admin_token")
    if not device or not token:
        raise HTTPException(400, "没有待激活设备")
    try:
        result = GatewayClient(device.gateway_url, token).activation(device.device_id)
        if result.get("status") == "active":
            device.status = "active"
            device.pending_device_token_encrypted = None
            device.last_error_code = None
            audit(db, "push_device_activated", f"device={device.device_id}")
        else:
            device.last_error_code = str(result.get("status", "pending_activation"))[:60]
    except GatewayFailure as exc:
        device.last_error_code = exc.code
    db.commit()
    return RedirectResponse("/push", status_code=303)


@app.post("/push/channel", name="push_channel")
def push_channel(
    request: Request,
    channel: str = Form(...),
    confirm: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    if channel not in {"wxpusher", "fcm_gateway"} or confirm != "yes":
        raise HTTPException(400, "请选择通道并确认切换")
    if channel == "fcm_gateway" and not db.scalar(select(PushDevice).where(PushDevice.status == "active")):
        raise HTTPException(400, "Android 设备尚未激活")
    if channel == "wxpusher" and not (get_setting(db, "wxpusher_app_token") and get_setting(db, "wxpusher_uid")):
        raise HTTPException(400, "WxPusher 尚未配置")
    set_setting(db, "notification_channel", channel)
    audit(db, "notification_channel_changed", f"channel={channel}")
    db.commit()
    return RedirectResponse("/push", status_code=303)


@app.post("/push/test", name="push_test")
def push_test(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    enqueue_test_notification(db)
    audit(db, "push_test_enqueued", "Notification test queued for the frozen primary channel")
    db.commit()
    flush_notifications(db, 1)
    return RedirectResponse("/notifications", status_code=303)


@app.post("/push/revoke", name="push_revoke")
def push_revoke(
    request: Request,
    admin_password: str = Form(...),
    confirm: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    if confirm != "revoke" or not verify_password(get_setting(db, "admin_password_hash") or "", admin_password):
        raise HTTPException(400, "需要正确的管理员密码和吊销确认")
    device = db.scalar(
        select(PushDevice).where(PushDevice.status.in_(["pending_activation", "active", "revocation_pending"]))
        .order_by(PushDevice.created_at.desc())
    )
    if not device:
        raise HTTPException(404, "没有可吊销设备")
    with pause_notification_delivery():
        device.status = "revocation_pending"
        device.revoke_pending = True
        invalidate_revoked_device_envelopes(db)
        set_setting(db, "notification_channel", "wxpusher")
        token = get_setting(db, "fcm_device_admin_token")
        if token:
            try:
                GatewayClient(device.gateway_url, token).revoke(device.device_id)
                finish_local_revocation(device)
            except GatewayFailure as exc:
                device.last_error_code = exc.code
    audit(db, "push_device_revocation_requested", f"device={device.device_id}")
    db.commit()
    return RedirectResponse("/push", status_code=303)


@app.post("/notifications/{notification_id}/retry")
def notification_retry(notification_id: int, request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    row = db.get(Notification, notification_id)
    if not row:
        raise HTTPException(404, "通知不存在")
    if not row.payload_encrypted:
        raise HTTPException(400, "通知内容已按安全策略清除，无法重发")
    row.status = NotificationStatus.PENDING.value
    row.next_attempt_at = utcnow()
    row.last_error = None
    db.commit()
    flush_notifications(db, 1)
    return RedirectResponse("/notifications", status_code=303)


@app.post("/notifications/retry-failed", name="notifications_retry_failed")
def notifications_retry_failed(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    rows = db.scalars(
        select(Notification).where(Notification.status == NotificationStatus.FAILED.value, Notification.payload_encrypted.is_not(None))
    ).all()
    for row in rows:
        row.status = NotificationStatus.PENDING.value
        row.next_attempt_at = utcnow()
        row.last_error = None
    db.commit()
    flush_notifications(db, min(20, len(rows)))
    return RedirectResponse("/notifications", status_code=303)


@app.get("/digests", response_class=HTMLResponse, name="digests")
def digests_page(request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    runs = db.scalars(select(DigestRun).order_by(DigestRun.created_at.desc()).limit(100)).all()
    types = due_digest_types(utcnow().astimezone())
    title, preview_html, item_count = build_digest(db, types)
    return render(
        request,
        "digests.html",
        digests=runs,
        runs=runs,
        preview_title=title,
        preview_html=preview_html,
        preview_count=item_count,
        digest_schedule={"daily": "20:30", "weekly": "周日 20:30", "monthly": "每月末 20:30"},
        active_nav="digests",
    )


@app.post("/digests/preview", response_class=HTMLResponse, name="digest_preview")
def digest_preview(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    types = due_digest_types(utcnow().astimezone())
    title, content, item_count = build_digest(db, types)
    runs = db.scalars(select(DigestRun).order_by(DigestRun.created_at.desc()).limit(100)).all()
    return render(
        request,
        "digests.html",
        digests=runs,
        preview_title=title,
        preview_html=content,
        preview_count=item_count,
        digest_schedule={"daily": "20:30", "weekly": "周日 20:30", "monthly": "每月末 20:30"},
        active_nav="digests",
    )


@app.get("/digests/{digest_id}", response_class=HTMLResponse, name="digest_detail")
def digest_detail(digest_id: int, request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    run = db.get(DigestRun, digest_id)
    if not run:
        raise HTTPException(404, "总结不存在")
    title = run.title or "历史邮箱总结"
    content = Cipher().decrypt_json(run.content_encrypted)["content"] if run.content_encrypted else "<p>该历史记录没有可用快照。</p>"
    item_count = run.item_count
    return render(
        request,
        "digests.html",
        digests=[run],
        preview_title=title,
        preview_html=content,
        preview_count=item_count,
        digest_schedule={"daily": "20:30", "weekly": "周日 20:30", "monthly": "每月末 20:30"},
        active_nav="digests",
    )


@app.get("/settings", response_class=HTMLResponse, name="settings")
def settings_page(request: Request, db: Session = Depends(get_db)):
    require_admin(request)
    return _render_settings(request, db)


def _render_settings(request: Request, db: Session, *, error: str | None = None, status_code: int = 200):
    configured = {
        "wxpusher": bool(get_setting(db, "wxpusher_app_token") and get_setting(db, "wxpusher_uid")),
        "llm": bool(get_setting(db, "llm_api_key") and get_setting(db, "llm_base_url") and get_setting(db, "llm_model")),
        "llm_base_url": get_setting(db, "llm_base_url", "") or "",
        "llm_model": get_setting(db, "llm_model", "") or "",
    }
    if configured["llm_base_url"]:
        try:
            normalize_model_url(configured["llm_base_url"])
        except ValueError:
            configured["llm"] = False
            configured["llm_base_url"] = ""
            error = error or "现有模型地址不符合 HTTPS 安全要求，云分类已暂停，请重新配置；本地规则继续运行"
    settings_view = {
        "quiet_start": "22:30",
        "quiet_end": "07:30",
        "urgent_override": True,
        "model_base_url": configured["llm_base_url"],
        "model_name": configured["llm_model"],
        "retention_days": settings.retention_days,
        "timezone": settings.timezone,
        "wxpusher_configured": configured["wxpusher"],
    }
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(50)).all()
    return render(request, "settings.html", configured=configured, settings=settings_view, audit_events=events, active_nav="settings", error=error, status_code=status_code)


@app.post("/settings", name="settings_update")
def settings_update(
    request: Request,
    wxpusher_app_token: str = Form(""),
    wxpusher_uid: str = Form(""),
    llm_base_url: str = Form("", alias="model_base_url"),
    llm_api_key: str = Form("", alias="model_api_key"),
    llm_model: str = Form("", alias="model_name"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    if llm_base_url.strip():
        try:
            llm_base_url = normalize_model_url(llm_base_url)
        except ValueError as exc:
            return _render_settings(request, db, error=str(exc), status_code=400)
    values = {
        "wxpusher_app_token": wxpusher_app_token,
        "wxpusher_uid": wxpusher_uid,
        "llm_base_url": llm_base_url,
        "llm_api_key": llm_api_key,
        "llm_model": llm_model,
    }
    for key, value in values.items():
        if value.strip():
            set_setting(db, key, value.strip())
    audit(db, "settings_updated", "Notification/model settings updated")
    db.commit()
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/test-wxpusher", name="settings_test_wxpusher")
def settings_test_wxpusher(request: Request, csrf_token: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request)
    _verify_csrf(request, csrf_token)
    enqueue_test_notification(db)
    db.commit()
    flush_notifications(db, 1)
    return RedirectResponse("/notifications", status_code=303)
