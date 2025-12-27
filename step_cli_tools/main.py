# --- Standard library imports ---
import os
import sys
from importlib.metadata import PackageNotFoundError, version

# Allows the script to be run directly and still find the package modules
if __name__ == "__main__" and __package__ is None:
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, parent_dir)
    __package__ = "step_cli_tools"

# --- Local application imports ---
from .common import *
from .configuration import *
from .support_functions import *
from .operations import *

# --- Main function ---


def main():
    """
    Entry point for the Step CLI Tools application.

    Returns:
        None
    """

    pkg_name = "step-cli-tools"
    profile_url = "https://github.com/LeoTN"
    try:
        pkg_version = version(pkg_name)
    except PackageNotFoundError:
        pkg_version = "development"

    # Verify and load the config file
    check_and_repair_config_file()
    config.load()

    # Check for updates and display version info
    if config.get("update_config.check_for_updates_at_launch"):
        include_prerelease = config.get(
            "update_config.consider_beta_versions_as_available_updates"
        )
        latest_version = check_for_update(
            pkg_version, include_prerelease=include_prerelease
        )
    else:
        latest_version = None

    if latest_version:
        latest_tag_url = f"{profile_url}/{pkg_name}/releases/tag/{latest_version}"
        version_text = (
            f"[#888888]Made by[/#888888] [link={profile_url} bold #FFFFFF]LeoTN[/link]"
            f"[#888888] - Update Available: [bold]{pkg_version}[/bold] → [/#888888]"
            f"[link={latest_tag_url} bold #FFFFFF]{latest_version}[/]\n"
        )
    else:
        version_text = (
            f"[#888888]Made by[/#888888] [link={profile_url} bold #FFFFFF]LeoTN[/link]"
            f"[#888888] - Version [bold]{pkg_version}[/]\n"
        )
    logo = """
[#F9ED69]     _                [#F08A5D]    _ _  [#B83B5E] _              _            [/]
[#F9ED69] ___| |_ ___ _ __     [#F08A5D]___| (_) [#B83B5E]| |_ ___   ___ | |___        [/]
[#F9ED69]/ __| __/ _ \\ '_ \\  [#F08A5D] / __| | | [#B83B5E]| __/ _ \\ / _ \\| / __|   [/]
[#F9ED69]\\__ \\ ||  __/ |_) | [#F08A5D]| (__| | | [#B83B5E]| || (_) | (_) | \\__ \\   [/]
[#F9ED69]|___/\\__\\___| .__/  [#F08A5D] \\___|_|_|[#B83B5E]  \\__\\___/ \\___/|_|___/ [/]
[#F9ED69]            |_|       [#F08A5D]           [#B83B5E]                           [/]
"""
    console.print(f"{logo}")
    console.print(version_text)

    # Ensure Step CLI is installed
    if not os.path.exists(STEP_BIN):
        console.print()
        answer = qy.confirm(
            "Step CLI not found. Do you want to install it now?",
            style=DEFAULT_QY_STYLE,
        ).ask()
        if answer:
            install_step_cli(STEP_BIN)
        else:
            console.print("[INFO] Exiting program.")
            sys.exit(0)

    # Define operations and their corresponding functions
    operation_switch = {
        "Install root CA on the system": operation1,
        "Uninstall root CA from the system (Windows & Linux)": operation2,
        "Configuration": show_config_operations,
        "Exit": sys.exit,
        None: sys.exit,
    }

    # Interactive menu loop
    while True:
        console.print()
        operation = show_operations(operation_switch)
        action = operation_switch.get(
            operation,
            lambda: console.print(
                f"[WARNING] Unknown operation: {operation}", style="#F9ED69"
            ),
        )
        console.print()
        action()
        console.print()


# --- Entry point ---
if __name__ == "__main__":
    main()
