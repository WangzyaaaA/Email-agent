from __future__ import annotations

import uvicorn

from push_gateway.config import get_gateway_settings


def main() -> None:
    settings = get_gateway_settings()
    uvicorn.run(
        "push_gateway.main:create_app",
        host=settings.host,
        port=settings.port,
        workers=1,
        proxy_headers=settings.trusted_proxy_headers,
        log_level=settings.log_level.lower(),
        factory=True,
    )


if __name__ == "__main__":
    main()
