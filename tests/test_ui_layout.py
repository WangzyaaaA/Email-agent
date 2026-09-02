from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "app" / "templates"
STYLES = ROOT / "app" / "static" / "styles.css"


def _render(template_name: str, **context: object) -> str:
    environment = Environment(
        loader=FileSystemLoader(TEMPLATES),
        autoescape=select_autoescape(("html",)),
    )
    return environment.get_template(template_name).render(
        url_for=lambda name, **values: f"/{name}",
        **context,
    )


def test_dense_pages_render_with_shared_section_spacing() -> None:
    otp = _render("otp_candidates.html", candidates=[], csrf_token="csrf")
    digests = _render(
        "digests.html",
        digests=[],
        digest_schedule={"daily": "20:30", "weekly": "周日 20:30", "monthly": "每月末 20:30"},
        csrf_token="csrf",
    )
    push = _render(
        "push.html",
        configured={"publisher": False, "device_admin": False, "gateway_url": ""},
        device=None,
        notification_channel="wxpusher",
        wxpusher_configured=True,
        csrf_token="csrf",
    )

    assert 'class="page-stack"' in otp
    assert 'class="page-stack"' in digests
    assert 'class="page-stack"' in push


def test_notification_channel_uses_accessible_choice_cards() -> None:
    page = _render(
        "push.html",
        configured={"publisher": False, "device_admin": False, "gateway_url": ""},
        device=None,
        notification_channel="wxpusher",
        wxpusher_configured=True,
        csrf_token="csrf",
    )

    assert '<fieldset class="channel-options">' in page
    assert '<legend class="visually-hidden">选择主通知通道</legend>' in page
    assert 'value="wxpusher" checked' in page
    assert 'value="fcm_gateway"' in page and 'value="fcm_gateway"  disabled' in page
    assert page.count('class="channel-choice-card"') == 2


def test_layout_styles_keep_native_radios_hidden_and_sections_separated() -> None:
    styles = STYLES.read_text(encoding="utf-8")

    assert ".page-stack { display: grid; gap: 18px; }" in styles
    assert ".channel-choice-input { position: absolute; width: 1px;" in styles
    assert ".channel-choice-input:focus-visible + .channel-choice-card" in styles
    assert ".gateway-form-grid { grid-template-columns: 1.25fr 1fr 1fr; }" in styles
