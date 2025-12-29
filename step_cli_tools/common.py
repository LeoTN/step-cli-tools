# --- Standard library imports ---
import os
import platform

# --- Third-party imports ---
import questionary
from rich.console import Console

__all__ = [
    "console",
    "qy",
    "DEFAULT_QY_STYLE",
    "SCRIPT_HOME_DIR",
    "STEP_BIN",
]

console = Console()
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
SCRIPT_HOME_DIR = os.path.expanduser("~/.step-cli-tools")


def get_step_binary_path() -> str:
    """
    Get the absolute path to the step-cli binary based on the operating system.

    Returns:
        str: Absolute path to the step binary.

    Raises:
        OSError: If the operating system is not supported.
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


STEP_BIN = get_step_binary_path()
