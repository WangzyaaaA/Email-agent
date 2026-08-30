from __future__ import annotations

import html
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ActionItem, ActionStatus, utcnow
from app.services.notifier import enqueue_notification


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def run_action_reminders(db: Session) -> int:
    now = utcnow()
    rows = db.scalars(
        select(ActionItem).where(
            ActionItem.status.in_([ActionStatus.NEW.value, ActionStatus.ACKNOWLEDGED.value, ActionStatus.SNOOZED.value]),
            ActionItem.due_at.is_not(None),
        )
    ).all()
    count = 0
    for item in rows:
        if item.snoozed_until and _as_utc(item.snoozed_until) > now:
            continue
        due = _as_utc(item.due_at)  # type: ignore[arg-type]
        remaining = due - now
        if item.kind == "followup":
            if remaining.total_seconds() <= 0 and not item.followup_sent:
                enqueue_notification(
                    db,
                    kind="followup",
                    priority="high",
                    title=item.title,
                    html_content=f"<h2>{html.escape(item.title)}</h2><p>这封请求已等待 3 天，尚未检测到回复。</p>",
                    preview="已等待 3 天，尚未检测到回复",
                    dedupe_key=f"followup:{item.id}",
                )
                item.followup_sent = True
                count += 1
            continue
        if remaining <= timedelta(hours=2) and not item.reminder_2_sent:
            enqueue_notification(
                db,
                kind="deadline",
                priority="critical",
                title=f"即将到期：{item.title}",
                html_content=f"<h2>{html.escape(item.title)}</h2><p>事项将在两小时内到期。</p>",
                preview="事项将在两小时内到期",
                dedupe_key=f"deadline-2h:{item.id}",
                expires_at=due,
                bypass_quiet=True,
            )
            item.reminder_2_sent = True
            count += 1
        elif remaining <= timedelta(hours=24) and not item.reminder_24_sent:
            enqueue_notification(
                db,
                kind="deadline",
                priority="high",
                title=f"明日到期：{item.title}",
                html_content=f"<h2>{html.escape(item.title)}</h2><p>事项将在 24 小时内到期。</p>",
                preview="事项将在 24 小时内到期",
                dedupe_key=f"deadline-24h:{item.id}",
            )
            item.reminder_24_sent = True
            count += 1
    db.commit()
    return count
