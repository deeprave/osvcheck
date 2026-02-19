"""Logging configuration and setup."""

import importlib.util
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


def is_rich_available() -> bool:
    """Check if rich module is available."""
    return importlib.util.find_spec("rich") is not None


class JSONFormatter(logging.Formatter):
    """JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


class ColorFormatter(logging.Formatter):
    """Color log formatter for console output."""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        color = self.COLORS.get(record.levelname, "")
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    use_json: bool = False,
    use_color: Optional[bool] = None,
    use_rich: bool = True,
) -> logging.Logger:
    """Setup and configure logging.

    Args:
        level: Logging level (DEBUG, INFO, WARNING)
        log_file: Optional file path for logging
        use_json: Output logs as JSON
        use_color: Enable color output (None = auto-detect)
        use_rich: Use rich console if available

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("osvcheck")
    logger.setLevel(level)
    logger.handlers.clear()

    # Auto-detect color support if not specified
    if use_color is None:
        use_color = sys.stderr.isatty()

    # Console handler
    if use_json:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(JSONFormatter())
    elif use_rich and use_color and is_rich_available():
        from rich.logging import RichHandler  # type: ignore[import-not-found]

        console_handler = RichHandler(
            rich_tracebacks=True,
            markup=False,
            show_time=False,
            show_path=False,
        )
    else:
        console_handler = logging.StreamHandler(sys.stderr)
        if use_color:
            console_handler.setFormatter(
                ColorFormatter(
                    "%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
        else:
            console_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )

    console_handler.setLevel(level)
    logger.addHandler(console_handler)

    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        if use_json:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
            )
        file_handler.setLevel(level)
        logger.addHandler(file_handler)

    return logger
