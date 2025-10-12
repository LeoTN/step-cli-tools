# --- Standard library imports ---
import os
import platform
import re
import ssl
import subprocess
import sys
import urllib.request
from importlib.metadata import PackageNotFoundError, version

# --- Third-party imports ---
import questionary
from rich.panel import Panel

# Allows the script to be run directly and still find the package modules
if __name__ == "__main__" and __package__ is None:
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, parent_dir)
    __package__ = "step_cli_tools"

# --- Local application imports ---
from .support_functions import *
from .validators import *

STEP_BIN = get_step_binary_path()
# Default style to use for questionary
DEFAULT_QY_STYLE = questionary.Style(
    [
        ("pointer", "fg:#F9ED69"),
        ("highlighted", "fg:#F08A5D"),
        ("question", "bold"),
        ("answer", "fg:#F08A5D"),
    ]
)


def show_operations(switch: dict[str | None, object]) -> str | None:
    """Display available operations and let the user select one interactively.

    Args:
        switch: Dictionary mapping option names (or None) to functions.

    Returns:
        The selected option name (str) or None if canceled.
    """
    # Filter out None from the displayed options
    options = [opt for opt in switch.keys() if opt is not None]

    # Prompt user to select an operation
    choice = questionary.select(
        "Operation:",
        style=DEFAULT_QY_STYLE,
        choices=options,
        use_search_filter=True,
        use_jk_keys=False,
    ).ask()

    return choice


# --- Operations ---


def operation1():
    warning_text = (
        "You are about to install a root CA on your system.\n"
        "This may pose a potential security risk to your device.\n"
        "Make sure you fully trust the CA before proceeding!"
    )
    console.print(Panel.fit(warning_text, title="WARNING", border_style="#F9ED69"))

    # Ask for CA server hostname/IP and optional port
    ca_input = questionary.text(
        "Enter the step CA server hostname or IP (optionally with :port)",
        style=DEFAULT_QY_STYLE,
        validate=HostnamePortValidator,
    ).ask()

    # Split host and port
    if ":" in ca_input:
        ca_server, port_str = ca_input.rsplit(":", 1)
        port = int(port_str)
    else:
        ca_server = ca_input
        # Default port for step-ca
        port = 9000

    # Check CA health endpoint
    ca_url = f"https://{ca_server}:{port}/health"
    console.print(f"[INFO] Checking CA health at {ca_url} ...")
    try:
        # Ignore SSL verification in case the root ca is not yet trusted
        context = ssl._create_unverified_context()
        with urllib.request.urlopen(ca_url, context=context, timeout=10) as response:
            output = response.read().decode("utf-8").strip()
            if "ok" in output.lower():
                console.print(f"[INFO] CA at {ca_url} is healthy.")
            else:
                console.print(
                    f"[ERROR] CA health check failed for {ca_url}. Is the port correct and the server available?",
                    style="red",
                )
                return
    except Exception as e:
        console.print(
            f"[ERROR] CA health check failed: {e}\n\nIs the port correct and the server available?",
            style="red",
        )
        return

    # Ask for fingerprint of the root certificate
    fingerprint = (
        questionary.text(
            "Enter the fingerprint of the root certificate (SHA-256, 64 hex chars)",
            style=DEFAULT_QY_STYLE,
            validate=SHA256Validator,
        )
        .ask()
        .replace(":", "")
    )

    # Build the ca bootstrap command
    bootstrap_args = [
        "ca",
        "bootstrap",
        "--ca-url",
        ca_url,
        "--fingerprint",
        fingerprint,
        "--install",
    ]

    console.print(f"[INFO] Running step ca bootstrap on {ca_url} ...")
    execute_step_command(bootstrap_args, STEP_BIN, interactive=True)


def operation2():
    """Uninstall a root CA certificate from the system trust store using its SHA-256 fingerprint."""

    warning_text = (
        "You are about to remove a root CA certificate from your system.\n"
        "This is a sensitive operation and can affect system security.\n"
        "Proceed only if you know what you are doing!"
    )
    console.print(Panel.fit(warning_text, title="WARNING", border_style="#F9ED69"))

    # Ask for fingerprint of the root certificate
    fingerprint = (
        questionary.text(
            "Enter the fingerprint of the root certificate (SHA-256, 64 hex chars)",
            style=DEFAULT_QY_STYLE,
            validate=SHA256Validator,
        )
        .ask()
        .replace(":", "")
    )

    # Determine platform
    system = platform.system()

    if system == "Windows":
        console.print(
            f"[INFO] Searching for certificate in Windows user ROOT store with fingerprint '{fingerprint}' ..."
        )
        cert_info = find_windows_cert_by_sha256(fingerprint)
        if not cert_info:
            console.print(
                f"[ERROR] Certificate with fingerprint '{fingerprint}' not found in Windows ROOT store.",
                style="red",
            )
            return
        thumbprint, cn = cert_info

        # Confirm the deletion
        answer = questionary.confirm(
            f"Do you really want to remove the certificate with CN: '{cn}'?",
            style=DEFAULT_QY_STYLE,
            default=False,
        ).ask()
        if not answer:
            console.print("[INFO] Operation cancelled by user.")
            return

        # Delete certificate via certutil
        delete_cmd = ["certutil", "-delstore", "-user", "ROOT", thumbprint]
        result = subprocess.run(delete_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            console.print(
                f"[INFO] Certificate with CN '{cn}' removed from Windows ROOT store."
            )
        else:
            console.print(
                f"[ERROR] Failed to remove certificate: {result.stderr.strip()}",
                style="red",
            )

    elif system == "Linux":
        console.print(
            f"[INFO] Searching for certificate in Linux trust store with fingerprint '{fingerprint}' ..."
        )
        cert_info = find_linux_cert_by_sha256(fingerprint)
        if not cert_info:
            console.print(
                f"[ERROR] Certificate with fingerprint '{fingerprint}' not found in Linux trust store.",
                style="red",
            )
            return
        cert_path, cn = cert_info

        # Confirm the deletion
        answer = questionary.confirm(
            f"Do you really want to remove the certificate with CN: '{cn}'?",
            style=DEFAULT_QY_STYLE,
            default=False,
        ).ask()
        if not answer:
            console.print("[INFO] Operation cancelled by user.")
            return

        try:
            # Check if it's a symlink and remove target first
            if os.path.islink(cert_path):
                target_path = os.readlink(cert_path)
                if os.path.exists(target_path):
                    subprocess.run(["sudo", "rm", target_path], check=True)

            subprocess.run(["sudo", "rm", cert_path], check=True)
            subprocess.run(["sudo", "update-ca-certificates", "--fresh"], check=True)
            console.print(
                f"[INFO] Certificate with CN '{cn}' removed from Linux trust store."
            )
        except subprocess.CalledProcessError as e:
            console.print(f"[ERROR] Failed to remove certificate: {e}", style="red")

    else:
        console.print(
            f"[ERROR] Unsupported platform: {system}",
            style="red",
        )


# --- Main function ---


def main():
    try:
        pkg_version = version("step-cli-tools")
    except PackageNotFoundError:
        pkg_version = "development"

    logo = """
[#F9ED69]     _                [#F08A5D]    _ _  [#B83B5E] _              _            [/]
[#F9ED69] ___| |_ ___ _ __     [#F08A5D]___| (_) [#B83B5E]| |_ ___   ___ | |___        [/]
[#F9ED69]/ __| __/ _ \\ '_ \\  [#F08A5D] / __| | | [#B83B5E]| __/ _ \\ / _ \\| / __|   [/]
[#F9ED69]\\__ \\ ||  __/ |_) | [#F08A5D]| (__| | | [#B83B5E]| || (_) | (_) | \\__ \\   [/]
[#F9ED69]|___/\\__\\___| .__/  [#F08A5D] \\___|_|_|[#B83B5E]  \\__\\___/ \\___/|_|___/ [/]
[#F9ED69]            |_|       [#F08A5D]           [#B83B5E]                           [/]
"""
    console.print(f"{logo}")
    console.print(
        f"[dim]Made by[/dim] [link=https://github.com/LeoTN bold]LeoTN[/link][dim] - Version[/] [link=https://github.com/LeoTN/step-cli-tools/releases/tag/{pkg_version} bold #FFFFFF]{pkg_version}[/]\n"
    )

    if not os.path.exists(STEP_BIN):
        answer = questionary.confirm(
            "Step CLI not found. Do you want to install it now?",
            style=DEFAULT_QY_STYLE,
            default=False,
        ).ask()
        if answer:
            install_step_cli(STEP_BIN)
        else:
            console.print("[INFO] Exiting program.")
            sys.exit(0)

    switch = {
        "Install root CA on the system": operation1,
        "Uninstall root CA from the system (Windows & Linux)": operation2,
        "Exit": sys.exit,
        None: sys.exit,
    }

    while True:
        console.print()
        operation = show_operations(switch)
        action = switch.get(
            operation,
            lambda: console.print(
                f"[WARNING] Unknown operation: {operation}", style="yellow"
            ),
        )
        console.print()
        action()


# --- Entry point ---
if __name__ == "__main__":
    main()
