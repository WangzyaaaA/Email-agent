from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services.detector import (
    detect_otp,
    expects_reply,
    extract_deadline,
    normalized_subject,
    sanitize_for_model,
    sender_domain,
)


RECEIVED = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)


def test_detect_otp_supports_chinese_numeric_and_english_alphanumeric_codes() -> None:
    match = detect_otp("登录验证码", "您的验证码为 123456，有效期 5 分钟。", RECEIVED)
    assert match is not None
    assert match.code == "123456"
    assert match.expires_at == RECEIVED + timedelta(minutes=5)
    assert 0.2 <= match.confidence <= 0.99

    match = detect_otp("Your verification code", "Use AB12C3 to sign in. Expires in 2 hours.", RECEIVED)
    assert match is not None
    assert match.code == "AB12C3"
    assert match.expires_at == RECEIVED + timedelta(hours=2)


def test_otp_requires_keyword_and_does_not_treat_order_or_amount_as_code() -> None:
    assert detect_otp("订单详情", "订单号：123456，金额：99.00 元。", RECEIVED) is None
    assert detect_otp("Your order", "Order number 123456 and total amount 99.00", RECEIVED) is None
    assert detect_otp("通知", "参考编号 ABC12345", RECEIVED) is None


def test_otp_does_not_promote_an_order_number_when_a_nearby_keyword_is_unrelated() -> None:
    # A keyword in the subject/body alone must not make a nearby order number
    # a credential; this is a common false-positive shape in transactional mail.
    assert detect_otp("验证码通知", "订单号是 123456，本邮件不包含验证码。", RECEIVED) is None


def test_otp_uses_nearest_code_and_caps_expiry() -> None:
    match = detect_otp(
        "通知",
        "订单号 123456。登录验证码是 654321，有效期 999 小时。",
        RECEIVED,
    )
    assert match is not None
    assert match.code == "654321"
    assert match.expires_at == RECEIVED + timedelta(minutes=24 * 60)


def test_sanitize_for_model_removes_tracking_urls_secrets_and_quoted_history() -> None:
    sanitized = sanitize_for_model(
        "账户提醒",
        "请查看 https://tracking.example/a?id=1\n验证码：123456\n密码: secret-pass\n\nFrom: old@example.com\n旧邮件中的秘密",
    )
    assert "https://" not in sanitized
    assert "tracking.example" not in sanitized
    assert "123456" not in sanitized
    assert "secret-pass" not in sanitized
    assert "旧邮件" not in sanitized
    assert "[已遮盖]" in sanitized
    assert sanitized.startswith("主题：账户提醒\n正文：")


def test_sanitize_for_model_limits_subject_and_body() -> None:
    result = sanitize_for_model("s" * 700, "body\n" + "x" * 50_000)
    assert len(result.split("\n", 1)[0]) == len("主题：") + 500
    assert len(result.split("正文：\n", 1)[1]) <= 20_000


def test_deadline_and_reply_helpers() -> None:
    now = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
    deadline = extract_deadline("请在 2025-01-03 18:00 前提交", now)
    assert deadline is not None
    assert deadline > now
    assert extract_deadline("这是一封普通通知", now) is None
    assert extract_deadline("截止时间是 2020-01-01", now) is None

    assert expects_reply("请回复确认是否参加")
    assert expects_reply("Please reply by Friday")
    assert not expects_reply("感谢您的来信，祝好")


def test_sender_domain_and_subject_normalization() -> None:
    assert sender_domain("Name <User@Example.COM>") == "example.com"
    assert sender_domain("invalid") == ""
    assert normalized_subject(" Re: 回复：FWD: 项目更新 ") == "项目更新"
