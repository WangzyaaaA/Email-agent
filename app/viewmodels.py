"""Presentation helpers for the server-rendered administration pages.

Templates must never invent fields that the ORM does not expose: the pages read
these view dictionaries so a missing attribute cannot silently fall back to a
placeholder such as "尚未同步" or "无截止时间". Formatting is centralized here so
dates always render in the configured timezone instead of raw UTC datetimes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from app.config import get_settings

PROVIDER_LABELS = {
    "qq": "QQ 邮箱",
    "gmail": "Gmail",
    "alibaba": "阿里企业邮箱",
    "custom": "自定义 IMAP",
}

MAILBOX_STATUS_LABELS = {
    "pending": "待连接",
    "connected": "已连接",
    "healthy": "同步正常",
    "error": "连接异常",
    "disabled": "已停用",
}

MAILBOX_STATUS_TONES = {
    "connected": "ok",
    "healthy": "ok",
    "pending": "warning",
    "error": "failed",
}

ACTION_STATUS_LABELS = {
    "new": "待处理",
    "acknowledged": "已确认",
    "snoozed": "已延期",
    "done": "已完成",
}

ACTION_STATUS_TONES = {
    "new": "warning",
    "acknowledged": "ok",
    "snoozed": "muted",
    "done": "ok",
}

NOTIFICATION_STATUS_LABELS = {
    "pending": "等待发送",
    "sending": "发送中",
    "sent": "已发送",
    "failed": "发送失败",
    "expired": "已过期",
}

NOTIFICATION_STATUS_TONES = {
    "sent": "ok",
    "failed": "failed",
    "expired": "muted",
    "pending": "warning",
    "sending": "warning",
}

NOTIFICATION_KIND_LABELS = {
    "otp": "验证码",
    "security": "安全告警",
    "important": "重要邮件",
    "deadline": "期限提醒",
    "followup": "待回复",
    "digest": "周期总结",
    "test": "测试通知",
}

PRIORITY_LABELS = {
    "low": "低",
    "normal": "普通",
    "high": "高",
    "critical": "紧急",
}

PRIORITY_TONES = {
    "critical": "critical",
    "high": "high",
    "normal": "normal",
    "low": "muted",
}

IMPORTANCE_LABELS = {
    "low": "低",
    "normal": "普通",
    "high": "重要",
    "critical": "紧急",
}

IMPORTANCE_TONES = {
    "critical": "critical",
    "high": "high",
    "normal": "normal",
    "low": "muted",
}

RISK_LABELS = {
    "verified": "认证通过",
    "unknown_auth": "认证未知",
    "authentication_failed": "认证失败",
}

RISK_TONES = {
    "verified": "ok",
    "unknown_auth": "warning",
    "authentication_failed": "failed",
}

RULE_KIND_LABELS = {
    "otp_address": "验证码发件人",
    "otp_domain": "验证码域名",
    "vip_address": "重要联系人",
    "vip_domain": "重要联系人域名",
}

PUSH_DEVICE_STATUS_LABELS = {
    "pending_activation": "待激活",
    "active": "已激活",
    "waiting_registration": "等待 FCM 登记",
    "revoked": "已吊销",
    "pairing_expired": "配对已过期",
}

DIGEST_TYPE_LABELS = {
    "daily": "每日总结",
    "weekly": "每周总结",
    "monthly": "每月总结",
}

DIGEST_STATUS_LABELS = {
    "sent": "已发送",
    "pending": "等待发送",
    "sending": "发送中",
    "failed": "发送失败",
    "expired": "已过期",
}

DIGEST_STATUS_TONES = {
    "sent": "ok",
    "failed": "failed",
    "expired": "muted",
    "pending": "warning",
    "sending": "warning",
}


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def local_timezone() -> ZoneInfo:
    return ZoneInfo(get_settings().timezone)


def local_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return _as_utc(value).astimezone(local_timezone())


def format_local(value: datetime | None, *, pattern: str = "%m-%d %H:%M", fallback: str = "—") -> str:
    local = local_datetime(value)
    return fallback if local is None else local.strftime(pattern)


def format_day(value: datetime | None) -> str:
    return format_local(value, pattern="%Y-%m-%d")


def day_bounds(now: datetime | None = None) -> tuple[datetime, datetime, datetime]:
    """Return UTC instants for the start of today, yesterday and tomorrow (local zone)."""
    local = local_datetime(now or datetime.now(timezone.utc))
    assert local is not None
    start_today = local.replace(hour=0, minute=0, second=0, microsecond=0)
    start_yesterday = start_today - timedelta(days=1)
    start_tomorrow = start_today + timedelta(days=1)
    return (
        start_today.astimezone(timezone.utc),
        start_yesterday.astimezone(timezone.utc),
        start_tomorrow.astimezone(timezone.utc),
    )


def delta_label(value: int) -> str:
    if value > 0:
        return f"+{value}"
    return str(value)


def _mapped(mapping: dict[str, str], value: str | None, fallback: str = "—") -> str:
    if not value:
        return fallback
    return mapping.get(value, value)


def mailbox_view(account) -> dict:  # noqa: ANN001 - ORM instance, kept duck-typed for tests.
    return {
        "id": account.id,
        "name": account.name,
        "email_address": account.email_address,
        "provider": account.provider,
        "provider_label": _mapped(PROVIDER_LABELS, account.provider, "IMAP"),
        "detected_provider": account.detected_provider,
        "detected_provider_label": _mapped(PROVIDER_LABELS, account.detected_provider or account.provider, "自定义 IMAP"),
        "status": account.status,
        "status_label": _mapped(MAILBOX_STATUS_LABELS, account.status, "待连接"),
        "status_tone": MAILBOX_STATUS_TONES.get(account.status, "pending"),
        "imap_host": account.imap_host,
        "imap_port": account.imap_port,
        "enabled": account.enabled,
        "last_error": account.last_error,
        "last_sync_label": format_local(account.last_sync_at) if account.last_sync_at else "尚未同步",
    }


def action_view(item, *, now: datetime | None = None) -> dict:  # noqa: ANN001
    current = _as_utc(now or datetime.now(timezone.utc))
    due = _as_utc(item.due_at) if item.due_at else None
    finished = item.status == "done"
    overdue = bool(due is not None and not finished and due < current)
    if due is None:
        due_label = "无截止时间"
        priority = "normal"
    elif overdue:
        due_label = f"已逾期 · {format_local(due)}"
        priority = "critical"
    else:
        due_label = format_local(due)
        remaining = due - current
        priority = "high" if remaining <= timedelta(hours=24) else "normal"
    return {
        "id": item.id,
        "title": item.title,
        "detail": item.detail,
        "kind": item.kind,
        "status": item.status,
        "status_label": _mapped(ACTION_STATUS_LABELS, item.status, "待处理"),
        "status_tone": ACTION_STATUS_TONES.get(item.status, "warning"),
        "is_overdue": overdue,
        "due_label": due_label,
        "priority": "normal" if finished else priority,
        "source_label": "来自邮件" if item.message_id else "本地创建",
        "created_label": format_local(item.created_at, pattern="%Y-%m-%d %H:%M"),
    }


def otp_candidate_view(candidate, subject: str | None) -> dict:  # noqa: ANN001
    return {
        "id": candidate.id,
        "sender_address": candidate.sender_address,
        "sender_domain": candidate.sender_domain,
        "subject": subject or "验证码邮件",
        "status": candidate.status,
        "risk": candidate.risk,
        "risk_label": _mapped(RISK_LABELS, candidate.risk, "需确认"),
        "risk_tone": RISK_TONES.get(candidate.risk, "warning"),
        "created_label": format_local(candidate.created_at, pattern="%Y-%m-%d %H:%M"),
    }


def notification_view(row) -> dict:  # noqa: ANN001
    return {
        "id": row.id,
        "kind": row.kind,
        "kind_label": _mapped(NOTIFICATION_KIND_LABELS, row.kind, row.kind),
        "title": row.title,
        "content_preview": row.content_preview,
        "channel": row.channel,
        "route": row.route,
        "priority": row.priority,
        "priority_label": _mapped(PRIORITY_LABELS, row.priority, "普通"),
        "priority_tone": PRIORITY_TONES.get(row.priority, "normal"),
        "status": row.status,
        "status_label": _mapped(NOTIFICATION_STATUS_LABELS, row.status, row.status),
        "status_tone": NOTIFICATION_STATUS_TONES.get(row.status, "pending"),
        "last_error": row.last_error,
        "attempts": row.attempts,
        "sent_label": format_local(row.sent_at or row.created_at, pattern="%Y-%m-%d %H:%M"),
    }


def digest_view(run, notification_status: str | None) -> dict:  # noqa: ANN001
    status = notification_status or "generated"
    period = format_day(run.created_at)
    types = [part for part in (run.digest_types or "").split(",") if part]
    return {
        "id": run.id,
        "period_key": run.period_key,
        "title": run.title,
        "period_label": period,
        "type_label": " / ".join(DIGEST_TYPE_LABELS.get(part, part) for part in types) or "周期总结",
        "status": status,
        "status_label": "已生成" if status == "generated" else _mapped(DIGEST_STATUS_LABELS, status, status),
        "status_tone": "muted" if status == "generated" else DIGEST_STATUS_TONES.get(status, "pending"),
        "item_count": run.item_count,
        "created_label": format_local(run.created_at, pattern="%Y-%m-%d %H:%M"),
        "preview": run.title or f"共 {run.item_count} 个条目",
    }


def message_view(message) -> dict:  # noqa: ANN001
    return {
        "id": message.id,
        "subject": message.subject,
        "summary": message.summary,
        "from_name": message.from_name,
        "from_address": message.from_address,
        "importance": message.importance,
        "importance_label": _mapped(IMPORTANCE_LABELS, message.importance, "普通"),
        "importance_tone": IMPORTANCE_TONES.get(message.importance, "muted"),
        "received_label": format_local(message.received_at, pattern="%m-%d %H:%M"),
    }


def rule_view(rule) -> dict:  # noqa: ANN001
    return {
        "id": rule.id,
        "kind": rule.kind,
        "kind_label": _mapped(RULE_KIND_LABELS, rule.kind, rule.kind),
        "value": rule.value,
        "enabled": rule.enabled,
    }


def audit_view(event) -> dict:  # noqa: ANN001
    return {
        "event_type": event.event_type,
        "detail": event.detail,
        "created_label": format_local(event.created_at, pattern="%Y-%m-%d %H:%M"),
    }


def push_device_status_label(status: str | None) -> str:
    return _mapped(PUSH_DEVICE_STATUS_LABELS, status, "未知状态")
