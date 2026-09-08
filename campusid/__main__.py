"""Entry point: ``python -m campusid``."""

from __future__ import annotations

import uvicorn

from campusid.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "campusid.app:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        log_config=None,  # structlog owns log formatting
        access_log=False,  # request logging arrives with the audit layer (M2)
        server_header=False,
        date_header=True,
    )


if __name__ == "__main__":
    main()
