from __future__ import annotations
from functools import lru_cache
from pathlib import Path


API_KEY = "SecureOps2026"

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)

try:
    import psutil
except ImportError:  # pragma: no cover - depends on deployment extras
    psutil = None


def auto_detect_interface():
    if psutil is None:
        return None

    interfaces = list(
        psutil.net_if_addrs().keys()
    )

    preferred = [
        "eth0",
        "eth1",
        "wlan0",
        "wlan1",
        "en0",
        "Ethernet",
        "Wi-Fi",
    ]

    for interface in preferred:

        if interface in interfaces:
            return interface

    for interface in interfaces:

        if interface != "lo":
            return interface

    return None


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="SECUREOPS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    interface: str | None = Field(default_factory=auto_detect_interface)
    lab_mode: bool = Field(default=True)
    packet_window_seconds: int = Field(
        default=10,
        ge=5,
    )

    max_packets_per_second: float = Field(
        default=50,
        gt=0,
    )

    max_unique_sources: int = Field(
        default=20,
        gt=0,
    )

    protocol_flood_threshold: int = Field(
        default=100,
        gt=0,
    )

    per_source_packet_threshold: int = Field(
        default=100,
        gt=0,
    )

    per_source_window_seconds: int = Field(
        default=10,
        ge=1,
    )
    
    
    
    database_path: Path = Field(
        default=Path(
            "data/secureops.sqlite3"
        )
    )
    
    virustotal_api_key: str = Field(
        default="",
    )
    max_alerts: int = Field(
        default=100,
        gt=0,
    )

    max_recent_packets: int = Field(
        default=100,
        gt=0,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
