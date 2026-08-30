from __future__ import annotations

import re

import dns.resolver

from app.mail.types import DetectionResult
from app.models import ProviderPreset


PRESETS: dict[str, tuple[str, int]] = {
    ProviderPreset.QQ.value: ("imap.qq.com", 993),
    ProviderPreset.GMAIL.value: ("imap.gmail.com", 993),
    ProviderPreset.ALIBABA.value: ("imap.qiye.aliyun.com", 993),
}


def preset_endpoint(provider: str) -> tuple[str, int] | None:
    return PRESETS.get(provider)


def _domain_from_email(email_address: str) -> str:
    if "@" not in email_address:
        raise ValueError("请输入完整邮箱地址")
    domain = email_address.rsplit("@", 1)[1].strip().lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9.-]+", domain):
        raise ValueError("邮箱域名格式不正确")
    return domain


def _host_has_suffix(host: str, suffix: str) -> bool:
    host = host.lower().rstrip(".")
    suffix = suffix.lower().rstrip(".")
    return host == suffix or host.endswith(f".{suffix}")


def detect_provider(email_address: str) -> DetectionResult:
    domain = _domain_from_email(email_address)
    if domain in {"gmail.com", "googlemail.com"}:
        return DetectionResult("gmail", "imap.gmail.com", 993, "high", ["邮箱域名属于 Gmail"])
    if domain in {"qq.com", "vip.qq.com", "foxmail.com"}:
        return DetectionResult("qq", "imap.qq.com", 993, "high", ["邮箱域名属于 QQ 邮箱"])

    evidence: list[str] = []
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_hosts = sorted(str(answer.exchange).lower().rstrip(".") for answer in answers)
        evidence.extend(f"MX: {host}" for host in mx_hosts)
        if any(_host_has_suffix(host, "qiye.aliyun.com") or _host_has_suffix(host, "mxhichina.com") for host in mx_hosts):
            return DetectionResult(
                "alibaba",
                "imap.qiye.aliyun.com",
                993,
                "high",
                evidence + ["MX 指向阿里企业邮箱；请确认后再输入三方客户端安全密码"],
            )
        if any(_host_has_suffix(host, "google.com") or _host_has_suffix(host, "googlemail.com") for host in mx_hosts):
            return DetectionResult("gmail", "imap.gmail.com", 993, "medium", evidence)
        if any(_host_has_suffix(host, "qq.com") for host in mx_hosts):
            return DetectionResult("qq", "imap.qq.com", 993, "medium", evidence)
    except Exception as exc:
        evidence.append(f"MX 查询未完成：{type(exc).__name__}")

    try:
        cname = dns.resolver.resolve(domain, "CNAME", lifetime=3)
        targets = [str(answer.target).lower().rstrip(".") for answer in cname]
        evidence.extend(f"CNAME: {target}" for target in targets)
        if any(_host_has_suffix(host, "qiye.aliyun.com") or _host_has_suffix(host, "mxhichina.com") for host in targets):
            return DetectionResult("alibaba", "imap.qiye.aliyun.com", 993, "medium", evidence)
        if any(_host_has_suffix(host, "google.com") or _host_has_suffix(host, "googlemail.com") for host in targets):
            return DetectionResult("gmail", "imap.gmail.com", 993, "medium", evidence)
        if any(_host_has_suffix(host, "qq.com") for host in targets):
            return DetectionResult("qq", "imap.qq.com", 993, "medium", evidence)
    except Exception:
        pass

    return DetectionResult(
        "custom",
        "",
        993,
        "unknown",
        evidence + ["无法确认底层服务商，请向企业管理员索取 IMAP SSL 地址"],
    )
