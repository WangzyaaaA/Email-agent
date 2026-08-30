from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PUSH_GATEWAY_",
        env_file=".env.gateway",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    master_key: str = Field(min_length=32)
    database_url: str = "sqlite:///./data/push_gateway.db"
    host: str = "127.0.0.1"
    port: int = 8090
    log_level: str = "INFO"
    firebase_project_id: str = Field(min_length=1)
    firebase_service_account_file: str = ""
    allow_http_for_tests: bool = False
    trusted_proxy_headers: bool = False
    max_request_bytes: int = 16_384
    max_clock_skew_seconds: int = 300
    request_rate_per_minute: int = 120
    status_retention_days: int = 7

    @field_validator("master_key")
    @classmethod
    def strong_master_key(cls, value: str) -> str:
        weak = ("development", "replace-with", "change-me", "example-")
        if value.lower().startswith(weak):
            raise ValueError("PUSH_GATEWAY_MASTER_KEY must be a random production secret")
        return value

    @field_validator("firebase_project_id")
    @classmethod
    def project_id_format(cls, value: str) -> str:
        if not value.replace("-", "").isalnum() or len(value) > 128:
            raise ValueError("Invalid Firebase project id")
        return value

    def ensure_data_dir(self) -> None:
        if self.database_url.startswith("sqlite:///"):
            raw = self.database_url.removeprefix("sqlite:///")
            if raw != ":memory:":
                Path(raw).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_gateway_settings() -> GatewaySettings:
    settings = GatewaySettings()  # type: ignore[call-arg]
    settings.ensure_data_dir()
    return settings
