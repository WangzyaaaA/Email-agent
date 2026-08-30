from __future__ import annotations

from email import policy
from email.parser import BytesParser

from imapclient.exceptions import IMAPClientError

from app.mail.imap_source import _safe_message, classify_connection_error, folder_role, text_parts_from_structure


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
