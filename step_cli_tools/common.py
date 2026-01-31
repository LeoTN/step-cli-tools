# --- Standard library imports ---
import logging
import platform
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlparse

# --- Third-party imports ---
import questionary
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

custom_logging_theme = Theme(
    {
        "logging.level.info": "none",
        "logging.level.warning": "#F9ED69",
        "logging.level.error": "#B83B5E",
        "logging.level.critical": "bold reverse #B83B5E",
    }
)
console = Console(theme=custom_logging_theme)
qy = questionary
# Default style to use for questionary
DEFAULT_QY_STYLE = qy.Style(
    [
        ("pointer", "fg:#F9ED69"),
        ("highlighted", "fg:#F08A5D"),
        ("question", "bold"),
        ("answer", "fg:#F08A5D"),
    ]
)

# --- Directories and files ---
SCRIPT_HOME_DIR = Path.home() / ".step-cli-tools"
SCRIPT_CACHE_DIR = SCRIPT_HOME_DIR / ".cache"
SCRIPT_CERT_DIR = SCRIPT_HOME_DIR / "certs"
SCRIPT_LOGGING_DIR = SCRIPT_HOME_DIR / "logs"

ALL_DIRS = [
    SCRIPT_HOME_DIR,
    SCRIPT_CACHE_DIR,
    SCRIPT_CERT_DIR,
    SCRIPT_LOGGING_DIR,
]


def _get_step_binary_path() -> Path:
    """
    Get the absolute path to the step-cli binary based on the operating system.

    Returns:
        The absolute path to the step-cli binary.
    """

    bin_dir = SCRIPT_HOME_DIR / "bin"
    system = platform.system()
    if system == "Windows":
        binary = bin_dir / "step.exe"
    elif system in ("Linux", "Darwin"):
        binary = bin_dir / "step"
    else:
        raise OSError(f"Unsupported platform: {system}")

    return binary


STEP_BIN = _get_step_binary_path()

# --- Logging ---


def _setup_logger(
    name: str,
    log_file: Path = SCRIPT_LOGGING_DIR / "step-cli-tools.log",
    level: int = logging.DEBUG,
    console: Console = console,
    max_bytes: int = 5_000_000,
    backup_count: int = 5,
) -> logging.Logger:
    """
    Sets up a reusable logger with Rich console output.

    Args:
        name: Name of the logger.
        log_file: Path to the log file.
        level: Logging level.
        console: Console instance used for output.
        max_bytes: Maximum size of log file in bytes.
        backup_count: Number of log files to keep.

    Returns:
        A logger instance.
    """

    # Ensure log directory exists
    if log_file.parent:
        log_file.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    # Avoid duplicate logs if root logger is configured
    logger.propagate = False

    if not logger.handlers:
        # Rotating file handler (plain text)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-8s [%(funcName)-30s] %(message)s"
            )
        )
        file_handler.setLevel(level)
        logger.addHandler(file_handler)

        # Rich console handler (colorful)
        console_handler = RichHandler(
            console=console, rich_tracebacks=True, show_time=False, show_path=False
        )
        console_handler.setLevel(level)
        logger.addHandler(console_handler)

    return logger


logger = _setup_logger(
    name="main",
)


def get_masked_url_for_logging(url: str) -> str:
    """
    Return a masked version of the URL suitable for logging.

    Args:
        url: The URL to mask

    Returns:
        A string containing only the scheme, hostname, and optional port
    """

    parsed_url = urlparse(url)
    scheme = parsed_url.scheme or "unknown"
    hostname = parsed_url.hostname or "unknown"
    port = parsed_url.port

    if port:
        return f"{scheme}://{hostname}:{port}"
    return f"{scheme}://{hostname}"
