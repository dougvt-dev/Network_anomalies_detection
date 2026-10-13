import logging

from common.config import settings


def setup_logging() -> None:
    logging.basicConfig(
        level=settings.LOG_LEVEL.upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
