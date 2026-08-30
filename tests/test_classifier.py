from __future__ import annotations

from datetime import datetime, timezone
import json

import httpx
import pytest

from app.models import Rule
from app.services import classifier
from app.services.classifier import (
    ClassificationResult,
    OpenAICompatibleClassifier,
    classify_hard,
    merge_classifications,
    safe_cloud_classify,
)


NOW = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)


def test_hard_classification_security_is_critical(db) -> None:
    result = classify_hard(db, "alerts@example.com", "安全告警：异地登录", "检测到新的登录", NOW)
    assert result.category == "security"
    assert result.importance == "critical"
    assert result.action_required is False
    assert result.confidence == 0.9


def test_hard_classification_deadline_and_urgent_rules(db) -> None:
    result = classify_hard(db, "normal@example.com", "项目提交", "请在 2025-01-02 18:00 前提交，务必完成", NOW)
    assert result.category == "work"
    assert result.importance == "high"
    assert result.action_required
    assert result.deadline is not None
    assert "48 小时" in result.reason


def test_hard_classification_vip_address_and_domain_rules(db) -> None:
    db.add_all(
        [
            Rule(kind="vip_address", value="boss@example.com", enabled=True),
            Rule(kind="vip_domain", value="partner.test", enabled=True),
            Rule(kind="vip_address", value="disabled@example.com", enabled=False),
        ]
    )
    db.flush()
    assert classify_hard(db, "BOSS@EXAMPLE.COM", "问候", "普通消息", NOW).importance == "normal"
    result = classify_hard(db, "a@partner.test", "需要确认", "请回复确认", NOW)
    assert result.importance == "high"
    assert result.action_required
    assert classify_hard(db, "disabled@example.com", "问候", "普通消息", NOW).importance == "low"


def test_hard_classification_category_precedence(db) -> None:
    result = classify_hard(db, "service@example.com", "支付与航班", "付款成功，航班已延误", NOW)
    assert result.category == "finance"


def test_classification_result_limits_text_and_validates_confidence() -> None:
    result = ClassificationResult(summary=" x " * 600, reason="r" * 1500, category="other")
    assert len(result.summary) == 1000
    assert len(result.reason) == 1000
    with pytest.raises(ValueError):
        ClassificationResult(confidence=1.1)


def test_merge_classifications_preserves_stronger_hard_signal() -> None:
    hard = ClassificationResult(category="security", importance="critical", reason="本地安全规则", action_required=True, confidence=0.9)
    cloud = ClassificationResult(category="other", importance="low", summary="云摘要", confidence=0.99)
    merged = merge_classifications(hard, cloud)
    assert merged.category == "security"
    assert merged.importance == "critical"
    assert merged.reason == "本地安全规则"
    assert merged.summary == "云摘要"
    assert merged.action_required
    assert merged.confidence == 0.99


def test_cloud_classifier_builds_expected_request_and_parses_fenced_json(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            payload = {
                "category": "security",
                "importance": "high",
                "summary": "提醒",
                "reason": "风险",
                "action_required": True,
                "confidence": 0.8,
            }
            return {"choices": [{"message": {"content": "```json\n" + json.dumps(payload, ensure_ascii=False) + "\n```"}}]}

    def fake_post(endpoint, **kwargs):
        captured["endpoint"] = endpoint
        captured["kwargs"] = kwargs
        return Response()

    monkeypatch.setattr(classifier.httpx, "post", fake_post)
    result = OpenAICompatibleClassifier("https://llm.example/v1/", "secret", "model-x").classify("a@example.com", "正文")
    assert result.category == "security"
    assert captured["endpoint"] == "https://llm.example/v1/chat/completions"
    assert captured["kwargs"]["headers"]["Authorization"] == "Bearer secret"
    assert captured["kwargs"]["json"]["temperature"] == 0
    assert "不可信数据" in captured["kwargs"]["json"]["messages"][0]["content"]


def test_safe_cloud_classify_contains_error_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args, **kwargs):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(classifier.httpx, "post", fail)
    result, error = safe_cloud_classify(OpenAICompatibleClassifier("http://llm", "k", "m"), "a@b", "text")
    assert result is None
    assert error is not None and error.startswith("ConnectError:")
