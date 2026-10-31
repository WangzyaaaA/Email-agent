from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="EMAIL_AGENT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    master_key: str = Field(default="development-only-change-this-master-key")
    database_url: str = "sqlite:///./data/mail_sentinel.db"
    host: str = "127.0.0.1"
    port: int = 8080
    timezone: str = "Asia/Shanghai"
    secure_cookies: bool = False
    trusted_proxy_headers: bool = False
    log_level: str = "INFO"
    retention_days: int = 90
    poll_seconds: int = 30
    reconciliation_seconds: int = 300
    initial_sync_days: int = 7
    initial_sync_limit: int = 500
    model_retry_ttl_hours: int = 24
    otp_retry_ttl_minutes: int = 15
    allow_loopback_gateway_for_tests: bool = False

    @field_validator("master_key")
    @classmethod
    def warn_short_key(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("EMAIL_AGENT_MASTER_KEY cannot be empty")
        return value

    def ensure_data_dir(self) -> None:
        if self.database_url.startswith("sqlite:///"):
            raw = self.database_url.removeprefix("sqlite:///")
            if raw != ":memory:":
                Path(raw).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)

    @property
    def production_key_configured(self) -> bool:
        weak_prefixes = ("development-only", "replace-with", "change-me", "example-")
        return len(self.master_key) >= 32 and not self.master_key.lower().startswith(weak_prefixes)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_data_dir()
    return settings
