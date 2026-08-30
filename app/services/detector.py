from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr

from dateparser.search import search_dates

from app.config import get_settings


OTP_KEYWORDS = re.compile(
    r"验证码|校验码|动态码|认证码|登录码|登录代码|安全码|一次性密码|"
    r"verification\s*code|security\s*code|one[- ]time(?:\s+password)?|\botp\b|passcode",
    re.IGNORECASE,
)
OTP_EXCLUSIONS = re.compile(
    r"订单|单号|金额|价格|合计|尾号|手机号|联系电话|快递|航班|车次|"
    r"order|amount|price|total|phone|tracking",
    re.IGNORECASE,
)
OTP_NEGATIONS = re.compile(r"不(?:包含|是|需要|提供).{0,4}(?:验证码|校验码|动态码)|(?:验证码|校验码).{0,4}(?:无效|已失效)", re.IGNORECASE)
NUMERIC_CODE = re.compile(r"(?<!\d)(\d{4,8})(?!\d)")
ALNUM_CODE = re.compile(r"(?<![A-Za-z0-9])(?=[A-Za-z0-9]{4,8}(?![A-Za-z0-9]))(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])([A-Za-z0-9]{4,8})(?![A-Za-z0-9])")
EXPIRY_PATTERN = re.compile(r"(?:有效(?:期)?|expires?|valid)[^\d]{0,12}(\d{1,3})\s*(分钟|分|min(?:ute)?s?|小时|hours?)", re.IGNORECASE)


@dataclass(slots=True)
class OtpMatch:
    code: str
    expires_at: datetime
    confidence: float


def detect_otp(subject: str, body: str, received_at: datetime) -> OtpMatch | None:
    combined = f"{subject}\n{body[:20_000]}"
    if OTP_NEGATIONS.search(body[:20_000]) and not re.search(r"(?:验证码|校验码|动态码|verification code)\s*(?:是|为|[:：])\s*[A-Za-z0-9]{4,8}", body, re.I):
        return None
    keyword_matches = list(OTP_KEYWORDS.finditer(combined))
    if not keyword_matches:
        return None
    candidates: list[tuple[float, str]] = []
    for pattern in (NUMERIC_CODE, ALNUM_CODE):
        for match in pattern.finditer(combined):
            code = match.group(1)
            start = max(0, match.start() - 60)
            end = min(len(combined), match.end() + 60)
            context = combined[start:end]
            nearest = min(abs(match.start() - keyword.start()) for keyword in keyword_matches)
            score = 1.0 / (1.0 + nearest / 20.0)
            if match.start() < len(subject) + 1:
                score += 0.4
            before = combined[max(0, match.start() - 30) : match.start()]
            exclusion_matches = list(OTP_EXCLUSIONS.finditer(before))
            exclusion_is_label = bool(exclusion_matches and len(before) - exclusion_matches[-1].end() <= 8)
            if exclusion_is_label:
                score -= 1.5
            elif OTP_EXCLUSIONS.search(context) and not OTP_KEYWORDS.search(context):
                score -= 0.8
            if code.isdigit() and len(code) in {6, 8}:
                score += 0.2
            candidates.append((score, code))
    if not candidates:
        return None
    score, code = max(candidates, key=lambda item: item[0])
    if score < 0.2:
        return None

    expiry_minutes = 10
    expiry_match = EXPIRY_PATTERN.search(combined)
    if expiry_match:
        amount = int(expiry_match.group(1))
        unit = expiry_match.group(2).lower()
        expiry_minutes = amount * 60 if "小时" in unit or "hour" in unit else amount
        expiry_minutes = min(expiry_minutes, 24 * 60)
    base = received_at if received_at.tzinfo else received_at.replace(tzinfo=timezone.utc)
    return OtpMatch(code=code, expires_at=base + timedelta(minutes=expiry_minutes), confidence=min(score, 0.99))


TRACKING_URL = re.compile(r"https?://\S+", re.IGNORECASE)
SECRET_PATTERN = re.compile(
    r"(?i)(验证码|校验码|动态码|认证码|verification\s*code|security\s*code|otp|password|密码|api\s*key|token|secret|访问密钥|登录凭证)"
    r"(\s*(?:是|为|[:：])?\s*)([A-Za-z0-9_-]{4,32})"
)


def sanitize_for_model(subject: str, body: str) -> str:
    text = body[:50_000]
    text = re.split(r"\n(?:From:|发件人：|-----Original Message-----)", text, maxsplit=1, flags=re.IGNORECASE)[0]
    text = re.split(r"\n--\s*\n", text, maxsplit=1)[0]
    text = TRACKING_URL.sub("[链接已移除]", text)
    text = SECRET_PATTERN.sub(lambda match: f"{match.group(1)}{match.group(2)}[已遮盖]", text)
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~-]{12,}", "Bearer [已遮盖]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{5,})?\b", "[JWT已遮盖]", text)
    text = re.sub(r"(?<![A-Za-z0-9])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9])", "[长凭据已遮盖]", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return f"主题：{subject[:500]}\n正文：\n{text[:20_000]}"


def extract_deadline(text: str, now: datetime | None = None) -> datetime | None:
    now = now or datetime.now(timezone.utc)
    settings = {
        "PREFER_DATES_FROM": "future",
        "RELATIVE_BASE": now,
        "RETURN_AS_TIMEZONE_AWARE": True,
        "TIMEZONE": get_settings().timezone,
        "TO_TIMEZONE": "UTC",
    }
    deadline_marker = re.search(
        r"(?:截止|到期|最晚|之前|前(?:提交|支付|完成|确认|回复)|deadline|due|expires?)[^。；;\n]{0,80}",
        text[:20_000],
        flags=re.IGNORECASE,
    )
    if not deadline_marker:
        return None
    start = max(0, deadline_marker.start() - 80)
    deadline_context = text[start : min(len(text), deadline_marker.end() + 40)]
    try:
        matches = search_dates(deadline_context, languages=["zh", "en"], settings=settings) or []
    except Exception:
        return None
    if not matches:
        return None
    value = matches[0][1]
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    if value < now - timedelta(hours=1) or value > now + timedelta(days=365 * 2):
        return None
    return value


def expects_reply(text: str) -> bool:
    return bool(
        re.search(
            r"请(?:回复|确认|反馈|告知)|烦请|期待.{0,6}回复|"
            r"please\s+(?:reply|confirm|respond)|let\s+me\s+know|could\s+you|would\s+you",
            text[:20_000],
            flags=re.IGNORECASE,
        )
    )


def sender_domain(address: str) -> str:
    parsed = parseaddr(address)[1].lower()
    return parsed.rsplit("@", 1)[1] if "@" in parsed else ""


def normalized_subject(subject: str) -> str:
    return re.sub(r"^(?:(?:re|fw|fwd|回复|转发)\s*[:：]\s*)+", "", subject.strip(), flags=re.IGNORECASE).lower()[:500]
