import logging
import logging.config
import os


LOG_FILE = "logs/decrypt0rX.log"
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s [%(levelname)s] [%(name)s] [%(threadName)s] %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
        "file": {
            "class": "logging.handlers.TimedRotatingFileHandler",
            "filename": LOG_FILE,
            "when": "midnight",
            "backupCount": 7,
            "formatter": "default",
        },
    },
    "root": {"level": "DEBUG", "handlers": ["console", "file"]},
}
