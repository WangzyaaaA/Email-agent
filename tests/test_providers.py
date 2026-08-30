from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.mail import providers
from app.mail.providers import detect_provider, preset_endpoint


def test_known_provider_presets_and_domains_do_not_query_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_resolve(*args, **kwargs):
        raise AssertionError("known domains should not use DNS")

    monkeypatch.setattr(providers.dns.resolver, "resolve", fail_resolve)
    assert preset_endpoint("qq") == ("imap.qq.com", 993)
    assert preset_endpoint("unknown") is None
    assert detect_provider("user@gmail.com").provider == "gmail"
    assert detect_provider("user@googlemail.com").host == "imap.gmail.com"
    assert detect_provider("user@vip.qq.com").provider == "qq"
    assert detect_provider("user@foxmail.com").confidence == "high"


@pytest.mark.parametrize("value", ["missing-at", "a@", "a@bad_domain.com", "a@中文.cn"])
def test_provider_detection_rejects_invalid_addresses(value: str) -> None:
    with pytest.raises(ValueError):
        detect_provider(value)


def test_mx_detection_recognizes_alibaba_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        providers.dns.resolver,
        "resolve",
        lambda domain, record_type, lifetime: [SimpleNamespace(exchange="mx1.qiye.aliyun.com.")],
    )
    result = detect_provider("user@corp.example")
    assert result.provider == "alibaba"
    assert result.host == "imap.qiye.aliyun.com"
    assert result.confidence == "high"
    assert any("MX:" in item for item in result.evidence)
    assert any("三方客户端安全密码" in item for item in result.evidence)


@pytest.mark.parametrize(
    ("mx", "provider", "host", "confidence"),
    [
        ("gmail-smtp-in.l.google.com.", "gmail", "imap.gmail.com", "medium"),
        ("mx.qq.com.", "qq", "imap.qq.com", "medium"),
    ],
)
def test_mx_detection_recognizes_google_and_qq(monkeypatch: pytest.MonkeyPatch, mx: str, provider: str, host: str, confidence: str) -> None:
    monkeypatch.setattr(providers.dns.resolver, "resolve", lambda *args, **kwargs: [SimpleNamespace(exchange=mx)])
    result = detect_provider("user@corp.example")
    assert (result.provider, result.host, result.confidence) == (provider, host, confidence)


def test_mx_errors_and_unrecognized_mx_fall_back_to_custom(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(providers.dns.resolver, "resolve", lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("dns")))
    result = detect_provider("user@corp.example")
    assert result.provider == "custom"
    assert result.port == 993
    assert "MX 查询未完成：TimeoutError" in result.evidence

    monkeypatch.setattr(providers.dns.resolver, "resolve", lambda *args, **kwargs: [SimpleNamespace(exchange="mx.other.test.")])
    result = detect_provider("user@corp.example")
    assert result.provider == "custom"
    assert result.evidence == ["MX: mx.other.test", "无法确认底层服务商，请向企业管理员索取 IMAP SSL 地址"]


def test_cname_detection_recognizes_google_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve(_domain: str, record_type: str, lifetime: int):
        if record_type == "MX":
            return [SimpleNamespace(exchange="mx.other.test.")]
        return [SimpleNamespace(target="mail.google.com.")]

    monkeypatch.setattr(providers.dns.resolver, "resolve", resolve)
    result = detect_provider("user@corp.example")
    assert (result.provider, result.host, result.confidence) == ("gmail", "imap.gmail.com", "medium")
