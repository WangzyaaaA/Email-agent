from __future__ import annotations

import html
import json
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.mail.parser import parse_mail
from app.mail.types import RemoteMessage
from app.models import (
    ActionItem,
    ActionStatus,
    FolderCheckpoint,
    MailboxAccount,
    MessageMetadata,
    OtpCandidate,
    ProcessingJob,
    Rule,
    utcnow,
)
from app.security import Cipher, mask_otp
from app.services.classifier import (
    ClassificationResult,
    classify_hard,
    configured_classifier,
    merge_classifications,
    safe_cloud_classify,
)
from app.services.detector import detect_otp, expects_reply, normalized_subject, sanitize_for_model, sender_domain
from app.services.notifier import enqueue_notification, important_html, otp_html
from app.store import audit


_processing_lock = threading.Lock()


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _otp_rule(db: Session, address: str) -> Rule | None:
    address = address.lower()
    domain = sender_domain(address)
    rules = db.scalars(
        select(Rule).where(Rule.enabled.is_(True), Rule.kind.in_(["otp_address", "otp_domain"]))
    ).all()
    return next(
        (
            rule
            for rule in rules
            if (rule.kind == "otp_address" and rule.value.lower() == address)
            or (rule.kind == "otp_domain" and rule.value.lower().lstrip("@") == domain)
        ),
        None,
    )


def _complete_replied_followups(db: Session, references: list[str], in_reply_to: str | None, subject: str) -> None:
    keys = {value for value in references if value}
    if in_reply_to:
        keys.add(in_reply_to)
    keys.add(f"subject:{normalized_subject(subject)}")
    if not keys:
        return
    rows = db.scalars(
        select(ActionItem).where(
            ActionItem.kind == "followup",
            ActionItem.status != ActionStatus.DONE.value,
            ActionItem.thread_key.in_(keys),
        )
    ).all()
    for row in rows:
        row.status = ActionStatus.DONE.value
        row.detail = f"{row.detail}\n已检测到回复，自动完成。".strip()


def _save_classification(message: MessageMetadata, result: ClassificationResult, llm_status: str) -> None:
    message.category = result.category
    message.importance = result.importance
    message.summary = result.summary
    message.reason = result.reason
    message.action_required = result.action_required
    message.deadline = result.deadline
    message.confidence = result.confidence
    message.llm_status = llm_status


def _ensure_action(db: Session, message: MessageMetadata, result: ClassificationResult, historical: bool = False) -> None:
    if not result.action_required and not result.deadline:
        return
    existing = db.scalar(select(ActionItem).where(ActionItem.message_id == message.id, ActionItem.kind == "deadline"))
    if existing:
        if result.deadline:
            existing.due_at = result.deadline
        return
    db.add(
        ActionItem(
            message_id=message.id,
            kind="deadline",
            title=result.summary or message.subject or "邮件待办",
            detail=result.reason,
            due_at=result.deadline,
            thread_key=message.thread_key,
            reminder_24_sent=historical,
            reminder_2_sent=historical,
        )
    )


def _enqueue_important(db: Session, message: MessageMetadata, historical: bool) -> None:
    if historical or message.importance not in {"high", "critical"}:
        return
    now = utcnow()
    deadline = _as_utc(message.deadline) if message.deadline else None
    due_within_two_hours = bool(deadline and deadline <= now + timedelta(hours=2))
    bypass = message.importance == "critical" or message.category == "security" or due_within_two_hours
    deadline_text = deadline.astimezone().strftime("%Y-%m-%d %H:%M") if deadline else None
    enqueue_notification(
        db,
        kind="security" if message.category == "security" else "important",
        priority=message.importance,
        title=message.subject or "重要邮件",
        html_content=important_html(message.subject or "重要邮件", message.summary, message.reason, deadline_text),
        preview=f"{message.summary}｜{message.reason}",
        dedupe_key=f"important:{message.id}",
        bypass_quiet=bypass,
    )


def process_remote_message(db: Session, account: MailboxAccount, remote: RemoteMessage) -> MessageMetadata | None:
    existing = db.scalar(
        select(MessageMetadata).where(
            MessageMetadata.account_id == account.id,
            MessageMetadata.folder == remote.folder,
            MessageMetadata.uidvalidity == remote.uidvalidity,
            MessageMetadata.uid == remote.uid,
        )
    )
    if existing:
        return existing

    auth_domains = {
        "gmail": ("google.com", "gmail.com"),
        "qq": ("qq.com",),
        "alibaba": ("aliyun.com", "qiye.aliyun.com", "mxhichina.com"),
    }.get(account.provider, ())
    parsed = parse_mail(remote.raw, fallback_date=remote.internal_date, trusted_auth_domains=auth_domains)
    direction = "sent" if remote.folder_role == "sent" else "inbox"
    subject_key = f"subject:{normalized_subject(parsed.subject)}"
    thread_key = parsed.message_id or parsed.in_reply_to or (parsed.references[-1] if parsed.references else subject_key)
    message = MessageMetadata(
        account_id=account.id,
        folder=remote.folder,
        uidvalidity=remote.uidvalidity,
        uid=remote.uid,
        message_id=parsed.message_id,
        thread_key=thread_key,
        direction=direction,
        from_address=parsed.from_address,
        from_name=parsed.from_name,
        to_addresses=",".join(parsed.to_addresses),
        subject=parsed.subject,
        received_at=parsed.received_at,
        auth_status=parsed.auth_status,
    )
    try:
        with db.begin_nested():
            db.add(message)
            db.flush()
    except IntegrityError:
        duplicate = db.scalar(
            select(MessageMetadata).where(
                MessageMetadata.account_id == account.id,
                MessageMetadata.folder == remote.folder,
                MessageMetadata.uidvalidity == remote.uidvalidity,
                MessageMetadata.uid == remote.uid,
            )
        )
        if duplicate:
            return duplicate
        raise

    if direction == "inbox":
        _complete_replied_followups(db, parsed.references, parsed.in_reply_to, parsed.subject)

    if direction == "sent":
        message.category = "sent"
        message.importance = "normal"
        message.summary = parsed.subject or "已发送邮件"
        message.reason = "用于待回复跟踪"
        message.llm_status = "not_used"
        if expects_reply(f"{parsed.subject}\n{parsed.text}"):
            db.add(
                ActionItem(
                    message_id=message.id,
                    kind="followup",
                    title=f"等待回复：{parsed.subject or '无主题邮件'}",
                    detail=f"收件人：{', '.join(parsed.to_addresses)}",
                    due_at=parsed.received_at + timedelta(days=3),
                    thread_key=parsed.message_id or subject_key,
                    followup_sent=remote.historical,
                )
            )
        db.commit()
        return message

    otp = detect_otp(parsed.subject, parsed.text, parsed.received_at)
    if otp:
        fingerprint = Cipher().fingerprint(f"{parsed.from_address}|{otp.code}|{parsed.received_at.isoformat()}")
        trusted = _otp_rule(db, parsed.from_address)
        status = "approved" if trusted else "pending"
        risk = "verified" if parsed.auth_status == "pass" else "unknown_auth"
        if parsed.auth_status == "fail":
            status = "blocked"
            risk = "authentication_failed"
        db.add(
            OtpCandidate(
                message_id=message.id,
                sender_address=parsed.from_address,
                sender_domain=sender_domain(parsed.from_address),
                code_fingerprint=fingerprint,
                status=status,
                risk=risk,
            )
        )
        message.category = "otp" if status == "approved" else "otp_candidate"
        message.importance = "critical" if status == "approved" else "normal"
        message.summary = "可信来源验证码" if status == "approved" else "发现新的验证码发件人候选"
        message.reason = "命中验证码规则与白名单" if status == "approved" else "需在控制台批准来源"
        message.confidence = otp.confidence
        if status == "approved" and not remote.historical:
            received_local = _as_utc(parsed.received_at).astimezone().strftime("%Y-%m-%d %H:%M:%S")
            expiry_local = _as_utc(otp.expires_at).astimezone().strftime("%Y-%m-%d %H:%M:%S")
            source = parsed.from_name or parsed.from_address
            enqueue_notification(
                db,
                kind="otp",
                priority="critical",
                title=f"{source} 验证码",
                html_content=otp_html(source, otp.code, received_local, expiry_local, parsed.auth_status),
                preview=f"{source}：{mask_otp(otp.code)}",
                dedupe_key=f"otp:{fingerprint}",
                expires_at=otp.expires_at,
                bypass_quiet=True,
            )
        elif parsed.auth_status == "fail" and not remote.historical:
            enqueue_notification(
                db,
                kind="security",
                priority="critical",
                title="已拦截可疑验证码邮件",
                html_content=(
                    f"<h2>已拦截可疑验证码</h2><p>发件人：{html.escape(parsed.from_address)}</p>"
                    "<p>邮件认证结果显示 SPF/DKIM/DMARC 失败，验证码未被发送。</p>"
                ),
                preview=f"{parsed.from_address} 的邮件认证失败",
                dedupe_key=f"otp-blocked:{message.id}",
                bypass_quiet=True,
            )
        db.commit()
        return message

    now = utcnow()
    hard = classify_hard(db, parsed.from_address, parsed.subject, parsed.text, now)
    result = hard
    llm_status = "not_configured"
    sanitized = sanitize_for_model(parsed.subject, parsed.text)
    classifier = configured_classifier(db)
    if classifier and not remote.historical:
        cloud, error = safe_cloud_classify(classifier, parsed.from_address, sanitized)
        if cloud:
            result = merge_classifications(hard, cloud)
            llm_status = "complete"
        else:
            llm_status = "retrying"
            db.add(
                ProcessingJob(
                    message_id=message.id,
                    payload_encrypted=Cipher().encrypt_json(
                        {
                            "sender": parsed.from_address,
                            "sanitized_text": sanitized,
                            "historical": remote.historical,
                        }
                    ),
                    expires_at=now + timedelta(hours=get_settings().model_retry_ttl_hours),
                    last_error=error,
                )
            )
    _save_classification(message, result, llm_status)
    _ensure_action(db, message, result, remote.historical)
    _enqueue_important(db, message, remote.historical)
    db.commit()
    return message


def retry_processing_jobs(db: Session, limit: int = 10) -> int:
    if not _processing_lock.acquire(blocking=False):
        return 0
    try:
        return _retry_processing_jobs_locked(db, limit)
    finally:
        _processing_lock.release()


def _retry_processing_jobs_locked(db: Session, limit: int = 10) -> int:
    now = utcnow()
    jobs = db.scalars(
        select(ProcessingJob).where(ProcessingJob.next_attempt_at <= now).order_by(ProcessingJob.created_at).limit(limit)
    ).all()
    if not jobs:
        return 0
    classifier = configured_classifier(db)
    completed = 0
    for job in jobs:
        expires = _as_utc(job.expires_at)
        if expires <= now or not job.payload_encrypted:
            message = db.get(MessageMetadata, job.message_id)
            if message:
                message.llm_status = "expired"
            db.delete(job)
            continue
        if not classifier:
            job.next_attempt_at = now + timedelta(minutes=10)
            continue
        # Short lease: a crash releases the job for recovery without letting another
        # scheduler in this deployment call the model concurrently.
        job.next_attempt_at = now + timedelta(minutes=5)
        db.commit()
        payload = Cipher().decrypt_json(job.payload_encrypted)
        cloud, error = safe_cloud_classify(classifier, payload["sender"], payload["sanitized_text"])
        if not cloud:
            job.attempts += 1
            job.last_error = error
            job.next_attempt_at = now + timedelta(seconds=min(1800, 2 ** min(job.attempts + 4, 10)))
            continue
        message = db.get(MessageMetadata, job.message_id)
        if message:
            hard = ClassificationResult(
                category=message.category,
                importance=message.importance,  # type: ignore[arg-type]
                summary=message.summary,
                reason=message.reason,
                action_required=message.action_required,
                deadline=message.deadline,
                confidence=message.confidence,
            )
            result = merge_classifications(hard, cloud)
            _save_classification(message, result, "complete")
            _ensure_action(db, message, result, bool(payload.get("historical")))
            _enqueue_important(db, message, bool(payload.get("historical")))
        job.payload_encrypted = None
        db.delete(job)
        completed += 1
    db.commit()
    return completed


def sync_account_with_source(account_id: int, source) -> int:  # MailSource protocol kept duck-typed for test fakes.
    from app.database import SessionLocal

    processed = 0
    with SessionLocal() as db:
        account = db.get(MailboxAccount, account_id)
        if not account or not account.enabled:
            return 0
        folders = [folder for folder in source.list_folders() if folder.role in {"inbox", "sent"}]
        for folder in folders:
            checkpoint = db.scalar(
                select(FolderCheckpoint).where(
                    FolderCheckpoint.account_id == account.id,
                    FolderCheckpoint.folder == folder.name,
                )
            )
            if not checkpoint:
                checkpoint = FolderCheckpoint(
                    account_id=account.id,
                    folder=folder.name,
                    role=folder.role,
                    uidvalidity="",
                    last_uid=0,
                    initialized=False,
                )
                db.add(checkpoint)
                db.flush()
            messages, last_uid, uidvalidity = source.fetch_new(
                folder,
                checkpoint.uidvalidity,
                checkpoint.last_uid,
                checkpoint.initialized,
            )
            for remote in messages:
                if process_remote_message(db, account, remote) is not None:
                    processed += 1
            checkpoint.uidvalidity = uidvalidity
            checkpoint.last_uid = last_uid
            checkpoint.initialized = True
            checkpoint.role = folder.role
            db.commit()
        account.last_sync_at = utcnow()
        account.status = "healthy"
        account.last_error = None
        account.last_error_code = None
        db.commit()
    return processed
