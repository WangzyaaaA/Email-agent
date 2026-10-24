from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]

# Version at which each advisory is fixed. The declared constraints must keep
# these versions installable; a lower cap (for example "cryptography<47")
# silently pins the deployment to a vulnerable release.
SECURITY_FLOORS = {
    "cryptography": "50.0.2",
    "certifi": "2026.10.19",
    "pillow": "13.0.0",
}
TEST_SECURITY_FLOORS = {
    "pytest": "9.0.3",
}


def _requirements(*groups: str) -> dict[str, Requirement]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    entries = list(project["dependencies"])
    for group in groups:
        entries.extend(project["optional-dependencies"][group])
    return {requirement.name: requirement for requirement in map(Requirement, entries)}


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
        "**/google-services.json",
        "android/local.properties",
        "android/**/build/",
        "deploy/push-gateway/secrets/",
    } <= entries


def test_android_firebase_configuration_is_excluded_from_git() -> None:
    entries = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "/android/**/google-services.json" in entries


def test_dependency_constraints_allow_the_patched_runtime_versions() -> None:
    requirements = _requirements("test", "gateway")
    for name, floor in SECURITY_FLOORS.items():
        requirement = requirements[name]
        assert requirement.specifier.contains(floor), (
            f"{name} 的约束 {requirement.specifier} 排除了已修复版本 {floor}"
        )


def test_test_dependency_constraints_allow_the_patched_pytest() -> None:
    requirements = _requirements("test")
    for name, floor in TEST_SECURITY_FLOORS.items():
        requirement = requirements[name]
        assert requirement.specifier.contains(floor), (
            f"{name} 的约束 {requirement.specifier} 排除了已修复版本 {floor}"
        )
