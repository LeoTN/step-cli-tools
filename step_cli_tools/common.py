# --- Standard library imports ---
import os
import platform

# --- Third-party imports ---
import questionary
from rich.console import Console

__all__ = [
    "console",
    "qy",
    "STEP_BIN",
    "DEFAULT_QY_STYLE",
]

console = Console()
qy = questionary


def get_step_binary_path() -> str:
    """Return absolute path to step-cli binary depending on OS."""
    home = os.path.expanduser("~")
    system = platform.system()
    if system == "Windows":
        return os.path.join(home, "bin", "step.exe")
    elif system in ("Linux", "Darwin"):
        return os.path.join(home, "bin", "step")
    else:
        raise OSError(f"Unsupported platform: {system}")


STEP_BIN = get_step_binary_path()
# Default style to use for questionary
DEFAULT_QY_STYLE = qy.Style(
    [
        ("pointer", "fg:#F9ED69"),
        ("highlighted", "fg:#F08A5D"),
        ("question", "bold"),
        ("answer", "fg:#F08A5D"),
    ]
)
