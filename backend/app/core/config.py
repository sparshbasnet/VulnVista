from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: str = "development"
    log_level: str = "INFO"
    secret_key: str = "dev-secret-change-me"

    database_url: str = "postgresql+asyncpg://vulnvista:vulnvista@postgres:5432/vulnvista"

    backend_cors_origins: str = "http://localhost:5173"
    backend_storage_dir: str = "/data/uploads"

    zap_api_url: str = "http://zap:8080"
    zap_api_key: str = "vulnvista-dev-key"

    # Optional — raises the NVD CVE API's rate limit from 5 to 50 requests per
    # rolling 30s window. Free signup at https://nvd.nist.gov/developers/request-an-api-key.
    # Unset means the vulnerable_services detector paces itself to the unauthenticated limit.
    nvd_api_key: str | None = None

    # Hosts that are auto-approved for scanning with no user acknowledgment —
    # the bundled lab containers. Any other host can still be scanned, but only
    # once the requester explicitly confirms they're authorized to test it
    # (see api/v1/targets.py). This is a convenience trust list, not a hard cap.
    lab_allowed_hosts: str = (
        "dvwa,juice-shop,vulnvista_dvwa,vulnvista_juice_shop,"
        "metasploitable2,vulnvista_metasploitable2,localhost,127.0.0.1"
    )

    # Hosts that can never be scanned, acknowledgment or not — cloud metadata
    # endpoints, whose only realistic use from a server-side HTTP client is SSRF.
    blocked_hosts: str = "169.254.169.254,fd00:ec2::254"

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]

    @property
    def trusted_hosts(self) -> list[str]:
        return [host.strip().lower() for host in self.lab_allowed_hosts.split(",") if host.strip()]

    @property
    def blocklisted_hosts(self) -> list[str]:
        return [host.strip().lower() for host in self.blocked_hosts.split(",") if host.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
