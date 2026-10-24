from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml


DEPLOY = Path(__file__).resolve().parents[1] / "deploy" / "push-gateway"


def test_deployment_variants_preserve_gateway_storage_and_do_not_publish_api() -> None:
    standalone = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text(encoding="utf-8"))
    external = yaml.safe_load((DEPLOY / "docker-compose.external-nginx.yml").read_text(encoding="utf-8"))
    for compose in (standalone, external):
        gateway = compose["services"]["gateway"]
        assert not gateway.get("ports")
        assert "network_mode" not in gateway
        assert gateway["read_only"] is True
        assert gateway["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in gateway["security_opt"]
        assert "gateway-data:/data" in gateway["volumes"]
        assert gateway["environment"]["PUSH_GATEWAY_DATABASE_URL"] == "sqlite:////data/push_gateway.db"
        assert gateway["environment"]["PUSH_GATEWAY_TRUSTED_PROXY_HEADERS"] == "true"
        assert "gateway-data" in compose["volumes"]
    assert {
        key: value for key, value in standalone["services"]["gateway"].items() if key != "networks"
    } == {
        key: value for key, value in external["services"]["gateway"].items() if key != "networks"
    }
    assert set(external["services"]) == {"gateway"}
    assert external["networks"]["nginx"] == {"external": True, "name": "nginx"}
    assert "mail-sentinel-push-gateway" in external["services"]["gateway"]["networks"]["nginx"]["aliases"]


def test_standalone_nginx_exposes_only_tls_and_keeps_certificates_read_only() -> None:
    compose = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text(encoding="utf-8"))
    nginx = compose["services"]["nginx"]
    assert nginx["ports"] == ["443:8443"]
    assert nginx["read_only"] is True
    assert nginx["cap_drop"] == ["ALL"]
    # Compose turns $$ into $; envsubst must never consume Nginx request variables.
    assert nginx["environment"]["NGINX_ENVSUBST_FILTER"] == "^PUSH_GATEWAY_DOMAIN$$"
    assert set(nginx["environment"]) == {"PUSH_GATEWAY_DOMAIN", "NGINX_ENVSUBST_FILTER"}
    certificate_mount = next(mount for mount in nginx["volumes"] if isinstance(mount, dict))
    assert certificate_mount["target"] == "/etc/nginx/ssl"
    assert certificate_mount["read_only"] is True
    assert certificate_mount["bind"]["create_host_path"] is False


@pytest.mark.parametrize("filename", ["nginx-gateway.conf.template", "nginx-mail.conf"])
def test_nginx_sites_protect_signed_requests_payloads_and_logs(filename: str) -> None:
    config = (DEPLOY / filename).read_text(encoding="utf-8")
    config = re.sub(r"(?m)^\s*#.*$", "", config)
    assert "client_max_body_size 16k;" in config
    assert "client_body_in_file_only off;" in config
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in config
    assert "proxy_pass http://$mail_sentinel_backend$request_uri;" in config
    assert "proxy_set_header X-Forwarded-Proto https;" in config
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in config
    assert "$proxy_add_x_forwarded_for" not in config
    assert "rewrite " not in config
    for directive in ("proxy_cache", "proxy_store", "proxy_request_buffering", "proxy_buffering"):
        assert f"{directive} off;" in config
    assert "proxy_max_temp_file_size 0;" in config
    formats = re.findall(r"log_format\s+mail_sentinel_safe\s+([^;]+);", config)
    assert len(formats) == 1
    assert set(re.findall(r"\$\w+", formats[0])) == {
        "$time_iso8601", "$status", "$body_bytes_sent", "$request_time"
    }
    for directive in re.findall(r"access_log\s+([^;]+);", config):
        assert directive == "off" or directive.endswith(" mail_sentinel_safe")
    assert set(re.findall(r"error_log\s+([^;]+);", config)) == {"/dev/null"}
