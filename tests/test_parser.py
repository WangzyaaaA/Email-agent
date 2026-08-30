from __future__ import annotations

from datetime import datetime, timezone
from email.message import EmailMessage

from app.mail.parser import MAX_BODY_CHARS, parse_mail


def _raw_message(
    *, plain: str | None = None, html: str | None = None, attachment: bytes | None = None, auth: str | None = None
) -> bytes:
    message = EmailMessage()
    message["From"] = "张三 <Sender@Example.com>"
    message["To"] = "Recipient@example.com, second@example.com"
    message["Cc"] = "Copy@example.com"
    message["Date"] = "Tue, 01 Jan 2030 12:34:56 +0800"
    message["Message-ID"] = "<message-1@example.com>"
    message["In-Reply-To"] = "<parent@example.com>"
    message["References"] = "<root@example.com> <parent@example.com>"
    message["Subject"] = "=?utf-8?b?5rWL6K+V?="
    if auth:
        message["Authentication-Results"] = auth
    if plain is not None and html is not None:
        message.set_content(plain)
        message.add_alternative(html, subtype="html")
    elif plain is not None:
        message.set_content(plain)
    else:
        message.set_content(html or "", subtype="html")
    if attachment is not None:
        message.add_attachment(attachment, maintype="application", subtype="pdf", filename="合同.pdf")
    return message.as_bytes()


def test_parse_mail_decodes_headers_addresses_and_thread_ids() -> None:
    parsed = parse_mail(_raw_message(plain="验证码是 123456"))
    assert parsed.subject == "测试"
    assert parsed.from_address == "sender@example.com"
    assert parsed.from_name == "张三"
    assert parsed.to_addresses == ["recipient@example.com", "second@example.com", "copy@example.com"]
    assert parsed.message_id == "<message-1@example.com>"
    assert parsed.in_reply_to == "<parent@example.com>"
    assert parsed.references == ["<root@example.com>", "<parent@example.com>"]
    assert parsed.received_at == datetime(2030, 1, 1, 4, 34, 56, tzinfo=timezone.utc)


def test_plain_text_is_preferred_over_html_and_attachment_is_not_body() -> None:
    parsed = parse_mail(_raw_message(plain="纯文本内容", html="<p>HTML 内容</p>", attachment=b"secret pdf"))
    assert parsed.text == "纯文本内容"
    assert "HTML" not in parsed.text
    assert "secret" not in parsed.text
    assert parsed.attachment_names == ["合同.pdf"]


def test_html_removes_active_content_and_extracts_visible_text() -> None:
    html = "<html><style>.x{}</style><script>alert(1)</script><svg>hidden</svg><body><h1>登录代码</h1><p>AB12C3</p></body></html>"
    parsed = parse_mail(_raw_message(html=html))
    assert "登录代码" in parsed.text
    assert "AB12C3" in parsed.text
    assert "alert" not in parsed.text
    assert "hidden" not in parsed.text


def test_authentication_results_prioritize_fail_and_handle_pass_unknown() -> None:
    assert parse_mail(_raw_message(plain="hello", auth="mx; spf=pass; dkim=pass"), trusted_auth_domains=("mx",)).auth_status == "pass"
    assert parse_mail(_raw_message(plain="hello", auth="mx; spf=pass; dkim=fail"), trusted_auth_domains=("mx",)).auth_status == "fail"
    assert parse_mail(_raw_message(plain="hello", auth="attacker.invalid; spf=pass"), trusted_auth_domains=("mx",)).auth_status == "unknown"
    assert parse_mail(_raw_message(plain="hello")).auth_status == "unknown"


def test_only_first_trusted_authentication_result_is_accepted() -> None:
    raw = _raw_message(plain="hello", auth="attacker.invalid; spf=pass")
    raw = raw.replace(
        b"Authentication-Results: attacker.invalid; spf=pass",
        b"Authentication-Results: attacker.invalid; spf=pass\r\nAuthentication-Results: mx.qq.com; spf=pass",
    )
    assert parse_mail(raw, trusted_auth_domains=("qq.com",)).auth_status == "unknown"


def test_received_spf_requires_a_real_trusted_top_hop() -> None:
    raw = _raw_message(plain="hello")
    marker = b"Subject: =?utf-8?b?5rWL6K+V?="
    trusted = raw.replace(marker, marker + b"\r\nReceived: from sender by mx.qq.com\r\nReceived-SPF: fail (sender policy)")
    spoofed = raw.replace(marker, marker + b"\r\nReceived: from sender by qq.com.evil.test\r\nReceived-SPF: pass")
    assert parse_mail(trusted, trusted_auth_domains=("qq.com",)).auth_status == "fail"
    assert parse_mail(spoofed, trusted_auth_domains=("qq.com",)).auth_status == "unknown"


def test_invalid_date_uses_fallback_and_body_is_bounded() -> None:
    raw = _raw_message(plain="x" * (MAX_BODY_CHARS + 100))
    raw = raw.replace(b"Date: Tue, 01 Jan 2030 12:34:56 +0800", b"Date: not-a-date")
    fallback = datetime(2025, 1, 1, tzinfo=timezone.utc)
    parsed = parse_mail(raw, fallback_date=fallback)
    assert parsed.received_at == fallback
    assert len(parsed.text) == MAX_BODY_CHARS
