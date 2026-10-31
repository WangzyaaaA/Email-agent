from __future__ import annotations

import math
from email import policy
from email.parser import BytesParser
from datetime import datetime, timezone

import pytest
from imapclient.exceptions import IMAPClientError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import database
from app.mail.imap_source import (
    FETCH_BATCH_SIZE,
    MAX_TEXT_TOTAL_BYTES,
    IMAPMailSource,
    _safe_message,
    classify_connection_error,
    folder_role,
    text_parts_from_structure,
)
from app.mail.types import FolderInfo
from app.models import FolderCheckpoint, MailboxAccount, Notification, Rule
from app.services.pipeline import sync_account_with_source


def test_bodystructure_selects_text_parts_and_skips_attachments() -> None:
    plain = (b"TEXT", b"PLAIN", (b"CHARSET", b"UTF-8"), None, None, b"QUOTED-PRINTABLE", 120, 3)
    html = (b"TEXT", b"HTML", (b"CHARSET", b"UTF-8"), None, None, b"BASE64", 240, 6)
    attached_text = (
        b"TEXT",
        b"PLAIN",
        (b"CHARSET", b"UTF-8", b"NAME", b"secret.txt"),
        None,
        None,
        b"BASE64",
        500,
        10,
        None,
        (b"ATTACHMENT", (b"FILENAME", b"secret.txt")),
    )
    structure = (plain, (html, attached_text, b"MIXED"), b"ALTERNATIVE")
    parts = text_parts_from_structure(structure)
    assert [(part.section, part.content_type) for part in parts] == [("1", "text/plain"), ("2.1", "text/html")]
    assert parts[0].charset == "UTF-8"
    assert parts[1].encoding == "base64"


def test_bodystructure_supports_imapclient_grouped_multipart_children() -> None:
    plain = (b"TEXT", b"PLAIN", (b"CHARSET", b"UTF-8"), None, None, b"QUOTED-PRINTABLE", 120, 3)
    html = (b"TEXT", b"HTML", (b"CHARSET", b"UTF-8"), None, None, b"BASE64", 240, 6)
    attached_text = (
        b"TEXT",
        b"PLAIN",
        (b"CHARSET", b"UTF-8", b"NAME", b"secret.txt"),
        None,
        None,
        b"BASE64",
        500,
        10,
        None,
        (b"ATTACHMENT", (b"FILENAME", b"secret.txt")),
    )
    mixed = ((html, attached_text), b"MIXED", (b"BOUNDARY", b"inner"), None, None)
    structure = ((plain, mixed), b"ALTERNATIVE", (b"BOUNDARY", b"outer"), None, None)

    parts = text_parts_from_structure(structure)

    assert [(part.section, part.content_type) for part in parts] == [("1", "text/plain"), ("2.1", "text/html")]


def test_fetch_failure_is_not_reported_as_connection_failure() -> None:
    code, message = classify_connection_error(
        IMAPClientError("fetch failed: Some messages could not be FETCHed (Failure)"),
        "gmail",
    )

    assert code == "message_fetch_failed"
    assert message.startswith("邮件同步失败")


def test_safe_message_keeps_metadata_but_contains_only_supplied_text() -> None:
    header = (
        b"From: sender@example.com\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Safe subject\r\n"
        b"Message-ID: <one@example.com>\r\n"
        b"Authentication-Results: mx.google.com; dkim=pass\r\n"
    )
    parts = text_parts_from_structure((b"TEXT", b"PLAIN", (b"CHARSET", b"UTF-8"), None, None, b"8BIT", 10, 1))
    raw = _safe_message(header, [(parts[0], "body only")])
    message = BytesParser(policy=policy.default).parsebytes(raw)
    assert message["Subject"] == "Safe subject"
    assert "body only" in message.get_body(preferencelist=("plain",)).get_content()
    assert "attachment" not in raw.decode(errors="ignore").lower()


def test_folder_roles_use_special_use_flags_before_localized_names() -> None:
    assert folder_role((b"\\Sent",), "anything") == "sent"
    assert folder_role((b"\\Trash",), "Deleted") == "trash"
    assert folder_role((), "收件箱") == "inbox"


class IncompleteClient:
    def __init__(self, missing: str | None = None):
        self.missing = missing
        self.uids = [11, 12, 13]
        self.empty_body = False

    def list_folders(self):
        return [((), "/", "INBOX")]

    def select_folder(self, folder, readonly):
        assert readonly is True
        return {b"UIDVALIDITY": 1}

    def search(self, criteria):
        return self.uids

    def fetch(self, uids, fields):
        assert any(str(field).startswith("BODY.PEEK[") for field in fields)
        if b"BODYSTRUCTURE" in fields:
            result = {}
            for uid in uids:
                if uid == 12 and self.missing == "metadata":
                    continue
                result[uid] = {
                    b"BODY[HEADER]": f"From: security@example.com\r\nSubject: Verification code\r\nMessage-ID: <{uid}@example.com>\r\n\r\n".encode(),
                    b"BODYSTRUCTURE": (b"TEXT", b"PLAIN", (b"CHARSET", b"UTF-8"), None, None, b"8BIT", 64, 1),
                    b"INTERNALDATE": datetime(2026, 9, 14, 12, tzinfo=timezone.utc),
                }
                if uid == 12 and self.missing == "header":
                    result[uid].pop(b"BODY[HEADER]")
            return result
        return {
            uid: (
                {}
                if uid == 12 and self.missing == "section"
                else {b"BODY[1]<0>": b"" if self.empty_body else f"Verification code: {600000 + uid}".encode()}
            )
            for uid in uids
        }


@pytest.mark.parametrize("missing", ["metadata", "header", "section"])
@pytest.mark.parametrize("initialized", [True, False])
def test_incomplete_fetch_preserves_checkpoint_and_historical_retry(db, monkeypatch, missing, initialized) -> None:
    account = MailboxAccount(name="Test", email_address="user@example.com", provider="gmail", imap_host="imap.example.com", username="user", password_encrypted="unused", host_confirmed=True)
    db.add(account)
    db.flush()
    checkpoint = FolderCheckpoint(account_id=account.id, folder="INBOX", uidvalidity="1", last_uid=10, initialized=initialized)
    db.add_all([checkpoint, Rule(kind="otp_address", value="security@example.com")])
    db.commit()
    monkeypatch.setattr(database, "SessionLocal", lambda: Session(db.get_bind(), expire_on_commit=False))
    client = IncompleteClient(missing)
    source = IMAPMailSource("imap.example.com", 993, "user", "unused", "gmail")
    source.client = client
    with pytest.raises(IMAPClientError, match="fetch failed"):
        sync_account_with_source(account.id, source)
    db.expire_all()
    assert checkpoint.last_uid == 10 and checkpoint.initialized is initialized
    assert db.scalar(select(Notification)) is None
    client.missing = None
    assert sync_account_with_source(account.id, source) == 3
    db.expire_all()
    assert checkpoint.last_uid == 13 and checkpoint.initialized
    assert len(db.scalars(select(Notification)).all()) == (3 if initialized else 0)


def test_present_empty_section_is_a_complete_fetch() -> None:
    client = IncompleteClient()
    client.empty_body = True
    source = IMAPMailSource("imap.example.com", 993, "user", "unused", "gmail")
    source.client = client
    messages, highest, validity = source.fetch_new(FolderInfo("INBOX", "inbox"), "1", 10, True)
    assert len(messages) == 3 and highest == 13 and validity == "1"


class BatchFetchClient:
    """A mailbox whose messages expose ``part_count`` text sections each."""

    def __init__(self, count: int, *, part_count: int = 2) -> None:
        self.uids = list(range(100, 100 + count))
        self.part_count = part_count
        self.calls = 0
        self.body_calls = 0
        self.body_items: list[list[str]] = []

    def _structure(self) -> tuple:
        leaves = tuple(
            (b"TEXT", b"PLAIN" if index % 2 == 0 else b"HTML", (b"CHARSET", b"UTF-8"), None, None, b"8BIT", 16, 1)
            for index in range(self.part_count)
        )
        return (leaves, b"MIXED", (b"BOUNDARY", b"b"), None, None)

    def list_folders(self):
        return [((), "/", "INBOX")]

    def select_folder(self, folder, readonly):
        assert readonly is True
        return {b"UIDVALIDITY": b"7"}

    def search(self, criteria):
        return self.uids

    def fetch(self, uids, fields):
        self.calls += 1
        if b"BODYSTRUCTURE" in fields:
            return {
                uid: {
                    b"BODY[HEADER]": (
                        f"From: security@example.com\r\nSubject: Code for {uid}\r\n"
                        f"Message-ID: <{uid}@example.com>\r\n\r\n"
                    ).encode(),
                    b"BODYSTRUCTURE": self._structure(),
                    b"INTERNALDATE": datetime(2026, 9, 14, 12, tzinfo=timezone.utc),
                }
                for uid in uids
            }
        self.body_calls += 1
        self.body_items.append([str(field) for field in fields])
        return {
            uid: {
                f"BODY[{index + 1}]<0>".encode(): f"part {index} for {uid}".encode()
                for index in range(self.part_count)
            }
            for uid in uids
        }


def test_text_sections_use_one_fetch_per_chunk_instead_of_per_message() -> None:
    client = BatchFetchClient(70)
    source = IMAPMailSource("imap.example.com", 993, "user", "unused", "gmail")
    source.client = client

    messages, highest, validity = source.fetch_new(FolderInfo("INBOX", "inbox"), "", 0, False)

    assert len(messages) == 70
    assert highest == 169 and validity == "7"
    assert client.calls == 1 + math.ceil(70 / FETCH_BATCH_SIZE)
    assert client.body_calls == math.ceil(70 / FETCH_BATCH_SIZE)
    assert client.body_items[0] == ["BODY.PEEK[1]<0.262144>", "BODY.PEEK[2]<0.262144>"]
    parsed = BytesParser(policy=policy.default).parsebytes(messages[0].raw)
    assert "part 0 for 100" in parsed.get_body(preferencelist=("plain",)).get_content()


def test_four_part_message_stays_inside_the_total_text_budget() -> None:
    client = BatchFetchClient(3, part_count=4)
    source = IMAPMailSource("imap.example.com", 993, "user", "unused", "gmail")
    source.client = client

    messages, highest, _validity = source.fetch_new(FolderInfo("INBOX", "inbox"), "", 0, False)

    assert len(messages) == 3 and highest == 102
    items = client.body_items[0]
    assert len(items) == 4
    caps = [int(item.rsplit("<0.", 1)[1].rstrip(">")) for item in items]
    assert max(caps) * len(caps) <= MAX_TEXT_TOTAL_BYTES
