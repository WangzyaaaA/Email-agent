from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from push_gateway.config import get_gateway_settings
from push_gateway.database import create_gateway_engine, create_session_factory, init_gateway_db
from push_gateway.models import Device, GatewayCredential, GatewayMessage, OperationalEvent, utcnow
from push_gateway.security import GatewayCipher, new_token


def operational_status_lines(db: Session, *, now: datetime | None = None) -> list[str]:
    """Return aggregate, non-sensitive values suitable for local monitoring."""
    current = now or utcnow()
    device_counts = dict(db.execute(select(Device.status, func.count()).group_by(Device.status)).all())
    message_counts = dict(db.execute(select(GatewayMessage.status, func.count()).group_by(GatewayMessage.status)).all())
    pending_statuses = ("accepted", "retrying", "leased", "waiting_registration")
    oldest = db.scalar(select(func.min(GatewayMessage.created_at)).where(GatewayMessage.status.in_(pending_statuses)))
    if oldest is None:
        oldest_age = 0
    else:
        aware_oldest = oldest.replace(tzinfo=timezone.utc) if oldest.tzinfo is None else oldest.astimezone(timezone.utc)
        oldest_age = max(0, int((current.astimezone(timezone.utc) - aware_oldest).total_seconds()))
    recent_events = dict(
        db.execute(
            select(OperationalEvent.code, func.count())
            .where(OperationalEvent.created_at >= current - timedelta(hours=24))
            .group_by(OperationalEvent.code)
        ).all()
    )
    device_text = ",".join(f"{key}:{device_counts[key]}" for key in sorted(device_counts)) or "none"
    message_text = ",".join(f"{key}:{message_counts[key]}" for key in sorted(message_counts)) or "none"
    event_text = ",".join(f"{key}:{recent_events[key]}" for key in sorted(recent_events)) or "none"
    return [
        f"devices={device_text}",
        f"messages={message_text}",
        f"oldest_pending_age_seconds={oldest_age}",
        f"operational_events_24h={event_text}",
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline Mail Sentinel Push Gateway credential management")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init", help="Create publisher and device-admin tokens and show each once")
    rotate = subparsers.add_parser("rotate", help="Add a new token version without revoking the old one")
    rotate.add_argument("scope", choices=("publisher", "device_admin"))
    subparsers.add_parser("list", help="List credential metadata without revealing tokens")
    subparsers.add_parser("status", help="Print aggregate delivery health without identifiers or payloads")
    revoke = subparsers.add_parser("revoke", help="Deactivate an old credential after its replacement is verified")
    revoke.add_argument("credential_id", type=int)
    args = parser.parse_args()

    settings = get_gateway_settings()
    engine = create_gateway_engine(settings)
    init_gateway_db(engine)
    factory = create_session_factory(engine)
    cipher = GatewayCipher(settings.master_key)
    if args.command == "list":
        with factory() as db:
            rows = db.scalars(select(GatewayCredential).order_by(GatewayCredential.kind, GatewayCredential.id)).all()
            for row in rows:
                print(f"id={row.id} scope={row.kind} active={str(row.active).lower()} created_at={row.created_at.isoformat()}")
        return
    if args.command == "status":
        with factory() as db:
            for line in operational_status_lines(db):
                print(line)
        return
    if args.command == "revoke":
        with factory() as db:
            row = db.get(GatewayCredential, args.credential_id)
            if not row or not row.active:
                raise SystemExit("Active credential not found")
            remaining = db.scalar(
                select(func.count()).select_from(GatewayCredential).where(
                    GatewayCredential.kind == row.kind,
                    GatewayCredential.active.is_(True),
                    GatewayCredential.id != row.id,
                )
            ) or 0
            if remaining < 1:
                raise SystemExit("Refusing to revoke the last active credential in this scope")
            row.active = False
            db.commit()
            print(f"revoked id={row.id} scope={row.kind}")
        return
    scopes = ["publisher", "device_admin"] if args.command == "init" else [args.scope]
    created: list[tuple[str, str, int]] = []
    with factory() as db:
        if args.command == "init":
            existing = db.scalar(select(GatewayCredential.id).limit(1))
            if existing:
                raise SystemExit("Gateway credentials already exist; use rotate instead")
        for scope in scopes:
            token = new_token()
            row = GatewayCredential(kind=scope, token_fingerprint=cipher.fingerprint(token), active=True)
            db.add(row)
            db.flush()
            created.append((scope, token, row.id))
        db.commit()
    print("Store these values now. They will not be shown again.")
    for scope, token, credential_id in created:
        print(f"{scope}_id={credential_id}")
        print(f"{scope}={token}")


if __name__ == "__main__":
    main()
