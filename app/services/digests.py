from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import ActionItem, ActionStatus, DigestRun, MessageMetadata, utcnow
from app.services.notifier import enqueue_notification
from app.security import Cipher


def _period_start(local_now: datetime, digest_type: str) -> datetime:
    if digest_type == "daily":
        return datetime.combine(local_now.date(), time.min, tzinfo=local_now.tzinfo)
    if digest_type == "weekly":
        return datetime.combine(local_now.date() - timedelta(days=6), time.min, tzinfo=local_now.tzinfo)
    return datetime.combine(local_now.date().replace(day=1), time.min, tzinfo=local_now.tzinfo)


def due_digest_types(local_now: datetime) -> list[str]:
    types = ["daily"]
    if local_now.weekday() == 6:
        types.append("weekly")
    if (local_now + timedelta(days=1)).month != local_now.month:
        types.append("monthly")
    return types


def build_digest(db: Session, digest_types: list[str], now: datetime | None = None) -> tuple[str, str, int]:
    zone = ZoneInfo(get_settings().timezone)
    local_now = (now or utcnow()).astimezone(zone)
    earliest = min(_period_start(local_now, digest_type) for digest_type in digest_types).astimezone(timezone.utc)
    messages = db.scalars(
        select(MessageMetadata).where(MessageMetadata.received_at >= earliest).order_by(MessageMetadata.received_at.desc())
    ).all()
    actions = db.scalars(
        select(ActionItem).where(ActionItem.status != ActionStatus.DONE.value).order_by(ActionItem.due_at.asc())
    ).all()
    counter = Counter(message.category for message in messages if message.direction == "inbox")
    important = [message for message in messages if message.importance in {"high", "critical"}]

    labels = {"daily": "今日", "weekly": "本周", "monthly": "本月"}
    title = " / ".join(labels[item] for item in digest_types) + "邮箱总结"
    sections = [f"<h2>{html.escape(title)}</h2>"]
    sections.append(f"<p>共处理 {len(messages)} 封邮件；重要邮件 {len(important)} 封；未完成事项 {len(actions)} 项。</p>")
    if counter:
        sections.append("<h3>分类统计</h3><ul>" + "".join(f"<li>{html.escape(key)}：{value}</li>" for key, value in counter.most_common()) + "</ul>")
    if important:
        sections.append("<h3>重要邮件</h3><ul>" + "".join(f"<li>{html.escape(item.summary or item.subject)}</li>" for item in important[:10]) + "</ul>")
    if actions:
        sections.append("<h3>待处理</h3><ul>" + "".join(f"<li>{html.escape(item.title)}</li>" for item in actions[:10]) + "</ul>")
    if not messages and not actions:
        sections.append("<p>本周期没有需要特别关注的事项。</p>")
    preview = f"处理 {len(messages)} 封，重要 {len(important)} 封，待办 {len(actions)} 项"
    return title, "".join(sections), len(messages) + len(actions)


def run_scheduled_digest(db: Session, now: datetime | None = None) -> DigestRun | None:
    zone = ZoneInfo(get_settings().timezone)
    local_now = (now or utcnow()).astimezone(zone)
    digest_types = due_digest_types(local_now)
    period_key = f"{local_now.date().isoformat()}:{','.join(digest_types)}"
    if db.scalar(select(DigestRun).where(DigestRun.period_key == period_key)):
        return None
    title, content, item_count = build_digest(db, digest_types, now)
    run = DigestRun(
        period_key=period_key,
        digest_types=",".join(digest_types),
        title=title,
        content_encrypted=Cipher().encrypt_json({"content": content}),
        item_count=item_count,
    )
    try:
        with db.begin_nested():
            db.add(run)
            db.flush()
    except IntegrityError:
        return None
    notification = enqueue_notification(
        db,
        kind="digest",
        priority="normal",
        title=title,
        html_content=content,
        preview=f"{title}，共 {item_count} 个条目",
        dedupe_key=f"digest:{period_key}",
    )
    run.notification_id = notification.id
    db.commit()
    return run
