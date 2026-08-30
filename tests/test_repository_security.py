from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_docker_build_context_excludes_local_secrets_and_artifacts() -> None:
    entries = {
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert {
        ".tools",
        ".env",
        "**/.env",
        "**/*.db",
        "**/*.sqlite3",
        "**/*.jks",
        "**/*.keystore",
        "android/local.properties",
        "android/**/build/",
        "deploy/push-gateway/secrets/",
    } <= entries
