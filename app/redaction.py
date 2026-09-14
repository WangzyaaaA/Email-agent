from __future__ import annotations

import re
from collections.abc import Iterable


OTP_LABEL = (
    r"验证码|校验码|动态码|认证码|登录码|登录代码|安全码|一次性密码|"
    r"verification\s*code|security\s*code|one[- ]time(?:\s+password)?|\botp\b|passcode"
)
SECRET_LABEL = OTP_LABEL + r"|password|密码|api[ _-]*key|token|secret|访问密钥|登录凭证"
SECRET_PATTERN = re.compile(
    rf"({SECRET_LABEL})(\s*(?:is|是|为|[:：=])?\s*)"
    r"([A-Za-z0-9][A-Za-z0-9._~+/=!?@#$%^&*_-]{3,})",
    re.IGNORECASE,
)
CODE_BEFORE_LABEL = re.compile(
    rf"(?<![A-Za-z0-9])([A-Za-z0-9]{{4,8}})(?![A-Za-z0-9])"
    rf"(\s*(?:is|是|为)?\s*(?:your|您的|你的|本次)?\s*(?:{OTP_LABEL}))",
    re.IGNORECASE,
)


def redact_sensitive_text(value: str, sensitive_values: Iterable[str] = ()) -> str:
    """Redact metadata and model text without truncating or retaining a secret."""
    for secret in sensitive_values:
        if secret:
            value = re.sub(
                rf"(?<![A-Za-z0-9]){re.escape(secret)}(?![A-Za-z0-9])",
                "[已遮盖]",
                value,
            )
    value = SECRET_PATTERN.sub(lambda match: f"{match.group(1)}{match.group(2)}[已遮盖]", value)
    value = CODE_BEFORE_LABEL.sub(lambda match: f"[已遮盖]{match.group(2)}", value)
    value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~-]{12,}", "Bearer [已遮盖]", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{5,})?\b", "[JWT已遮盖]", value)
    return re.sub(r"(?<![A-Za-z0-9])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9])", "[长凭据已遮盖]", value)
