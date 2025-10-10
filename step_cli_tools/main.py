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
from rich.panel import Panel

# Allows the script to be run directly and still find the package modules
if __name__ == "__main__" and __package__ is None:
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, parent_dir)
    __package__ = "step_cli_tools"

# --- Local application imports ---
from .support_functions import (
    console,
    ask_boolean_question,
    ask_string_question,
    get_step_binary_path,
    install_step_cli,
    execute_step_command,
    find_windows_cert_by_sha256,
    find_linux_cert_by_sha256,
)


STEP_BIN = get_step_binary_path()


def show_operations():
    """Print available operations inside a Rich Panel."""
    options = [
        "0) Exit",
        "1) Install root CA on the system",
        "2) Uninstall root CA from the system (Windows & Linux)",
    ]
    menu_text = "\n".join(options)
    console.print(Panel(menu_text, title="Available Operations", border_style="cyan"))


# --- Operations ---


def operation1():
    warning_text = (
        "You are about to install a root CA on your system.\n"
        "This may pose a potential security risk to your device.\n"
        "Make sure you fully trust the CA before proceeding!"
    )
    console.print(Panel.fit(warning_text, title="WARNING", border_style="yellow"))

    # Ask for CA server hostname or IP (optionally with port)
    ca_input = ask_string_question(
        "Enter the step CA server hostname or IP (optionally with :port)"
    )

    # Split host and port
    if ":" in ca_input:
        ca_server, port_str = ca_input.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            console.print(
                f"[ERROR] Invalid port '{port_str}'. Must be a number.", style="red"
            )
            return
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
        ask_string_question(
            "Enter the fingerprint of the root certificate (SHA-256, 64 hex chars)"
        )
        .strip()
        .replace(":", "")
        .lower()
    )

    # Validate format
    if not re.fullmatch(r"[A-Fa-f0-9]{64}", fingerprint):
        console.print(
            "[WARNING] The fingerprint does not match the expected format (64 hexadecimal characters).",
            style="yellow",
        )
        if not ask_boolean_question("Do you want to proceed anyway?"):
            console.print(
                "[INFO] Operation cancelled by user due to invalid fingerprint."
            )
            return
    console.print(f"[INFO] Using root CA fingerprint: {fingerprint}")

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
    console.print(Panel.fit(warning_text, title="WARNING", border_style="yellow"))

    # Ask for fingerprint of the root certificate
    fingerprint = (
        ask_string_question(
            "Enter the fingerprint of the root certificate (SHA-256, 64 hex chars)"
        )
        .strip()
        .replace(":", "")
        .lower()
    )

    # Validate format
    if not re.fullmatch(r"[A-Fa-f0-9]{64}", fingerprint):
        console.print(
            "[WARNING] The fingerprint does not match the expected format (64 hexadecimal characters).",
            style="yellow",
        )
        if not ask_boolean_question("Do you want to proceed anyway?"):
            console.print(
                "[INFO] Operation cancelled by user due to invalid fingerprint."
            )
            return

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

        if not ask_boolean_question(
            f"Do you really want to remove the certificate with CN: '{cn}'?"
        ):
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

        if not ask_boolean_question(
            f"Do you really want to remove the certificate with CN: '{cn}'?"
        ):
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
    logo = (
        r"""
     _                    _ _   _              _     
 ___| |_ ___ _ __     ___| (_) | |_ ___   ___ | |___ 
/ __| __/ _ \ '_ \   / __| | | | __/ _ \ / _ \| / __|
\__ \ ||  __/ |_) | | (__| | | | || (_) | (_) | \__ \
|___/\__\___| .__/   \___|_|_|  \__\___/ \___/|_|___/
            |_|                                                                                                                        
"""
        + f"\nMade by LeoTN - Version {pkg_version}\n"
    )
    # Use normal print to preserve ASCII art formatting
    print(logo)

    if not os.path.exists(STEP_BIN):
        if ask_boolean_question("step CLI not found. Do you want to install it now?"):
            install_step_cli(STEP_BIN)
        else:
            console.print("[INFO] Exiting program.")
            sys.exit(0)

    while True:
        show_operations()
        choice = input("Operation number: ").strip()

        if choice == "0":
            console.print("[INFO] Exiting program.")
            sys.exit(0)
        elif choice == "1":
            operation1()
        elif choice == "2":
            operation2()
        else:
            console.print("[ERROR] Invalid operation. Please try again.", style="red")


# --- Entry point ---
if __name__ == "__main__":
    main()
