# --- Standard library imports ---
import logging
from logging.handlers import RotatingFileHandler
import os
import platform

# --- Third-party imports ---
import questionary
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

__all__ = [
    "console",
    "qy",
    "DEFAULT_QY_STYLE",
    "SCRIPT_HOME_DIR",
    "SCRIPT_LOGGING_DIR",
    "STEP_BIN",
    "logger",
]


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
SCRIPT_HOME_DIR = os.path.expanduser("~/.step-cli-tools")
SCRIPT_LOGGING_DIR = os.path.normpath(os.path.join(SCRIPT_HOME_DIR, "logs"))


def _get_step_binary_path() -> str:
    """
    Get the absolute path to the step-cli binary based on the operating system.

    Returns:
        str: Absolute path to the step binary.
    """

    bin_dir = os.path.join(SCRIPT_HOME_DIR, "bin")
    system = platform.system()
    if system == "Windows":
        binary = os.path.join(bin_dir, "step.exe")
    elif system in ("Linux", "Darwin"):
        binary = os.path.join(bin_dir, "step")
    else:
        raise OSError(f"Unsupported platform: {system}")

    return os.path.normpath(binary)


STEP_BIN = _get_step_binary_path()

# --- Logging ---


def _setup_logger(
    name: str,
    log_file: str = "step-cli-tools.log",
    level=logging.DEBUG,
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
    if os.path.dirname(log_file):
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

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
    log_file=os.path.join(SCRIPT_LOGGING_DIR, "step-cli-tools.log"),
)
