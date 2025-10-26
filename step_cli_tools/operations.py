# --- Standard library imports ---
import os
import platform
import subprocess

# --- Third-party imports ---
from rich.panel import Panel


# --- Local application imports ---
from .common import *
from .configuration import *
from .support_functions import *
from .validators import *

__all__ = [
    "show_operations",
    "operation1",
    "operation2",
]


def show_operations(switch: dict[str | None, object]) -> str | None:
    """
    Display available operations and let the user select one interactively.

    Args:
        switch (dict[str | None, object]): Dictionary mapping option names
            (or None) to their corresponding functions.

    Returns:
        str | None: The selected option name, or None if canceled.
    """
    # Filter out None from the displayed options
    options = [opt for opt in switch.keys() if opt is not None]

    # Prompt user to select an operation
    choice = qy.select(
        "Operation:",
        style=DEFAULT_QY_STYLE,
        choices=options,
        use_search_filter=True,
        use_jk_keys=False,
    ).ask()

    return choice


def operation1() -> None:
    """
    Perform the CA bootstrap operation.

    Prompts the user for the CA server and fingerprint, then executes
    the step-ca bootstrap command.

    Returns:
        None
    """
    warning_text = (
        "You are about to install a root CA on your system.\n"
        "This may pose a potential security risk to your device.\n"
        "Make sure you fully trust the CA before proceeding!"
    )
    console.print(Panel.fit(warning_text, title="WARNING", border_style="#F9ED69"))

    # Ask for CA hostname/IP and port
    default = config.get("ca_server_config.default_ca_server")
    ca_input = qy.text(
        "Enter the step CA server hostname or IP (optionally with :port)",
        default=default,
        style=DEFAULT_QY_STYLE,
        validate=HostnamePortValidator,
    ).ask()

    if not ca_input or not ca_input.strip():
        console.print("[INFO] Operation cancelled by user.")
        return

    # Parse host and port
    ca_server, _, port_str = ca_input.partition(":")
    port = int(port_str) if port_str else 9000
    ca_url = f"https://{ca_server}:{port}/health"

    console.print(f"[INFO] Checking CA health at {ca_url} ...")

    # Run the health check via helper
    trust_unknown_default = config.get(
        "ca_server_config.trust_unknow_ca_servers_by_default"
    )
    if not check_ca_health(ca_url, trust_unknown_default):
        # Either failed or user cancelled
        return

    # Ask for fingerprint
    fingerprint = qy.text(
        "Enter the fingerprint of the root certificate (SHA-256, 64 hex chars)",
        style=DEFAULT_QY_STYLE,
        validate=SHA256Validator,
    ).ask()
    # Check for empty input
    if not fingerprint or not fingerprint.strip():
        console.print("[INFO] Operation cancelled by user.")
        return
    fingerprint = fingerprint.replace(":", "")

    # Run step-ca bootstrap
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
    result = execute_step_command(bootstrap_args, STEP_BIN, interactive=True)
    if result:
        console.print(
            "[NOTE] You may need to restart your system for the changes to take full effect."
        )


def operation2() -> None:
    """
    Uninstall a root CA certificate from the system trust store.

    Prompts the user for the certificate fingerprint and removes it from
    the appropriate trust store based on the platform.

    Returns:
        None
    """
    warning_text = (
        "You are about to remove a root CA certificate from your system.\n"
        "This is a sensitive operation and can affect system security.\n"
        "Proceed only if you know what you are doing!"
    )
    console.print(Panel.fit(warning_text, title="WARNING", border_style="#F9ED69"))

    # Ask for fingerprint of the root certificate
    fingerprint = qy.text(
        "Enter the fingerprint of the root certificate (SHA-256, 64 hex chars)",
        style=DEFAULT_QY_STYLE,
        validate=SHA256Validator,
    ).ask()
    # Check for empty input
    if not fingerprint or not fingerprint.strip():
        console.print("[INFO] Operation cancelled by user.")
        return
    fingerprint = fingerprint.replace(":", "")

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
                style="#B83B5E",
            )
            return
        thumbprint, cn = cert_info

        # Confirm the deletion
        answer = qy.confirm(
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
            console.print(
                "[NOTE] You may need to restart your system for the changes to take full effect."
            )
        else:
            console.print(
                f"[ERROR] Failed to remove certificate: {result.stderr.strip()}",
                style="#B83B5E",
            )

    elif system == "Linux":
        console.print(
            f"[INFO] Searching for certificate in Linux trust store with fingerprint '{fingerprint}' ..."
        )
        cert_info = find_linux_cert_by_sha256(fingerprint)
        if not cert_info:
            console.print(
                f"[ERROR] Certificate with fingerprint '{fingerprint}' not found in Linux trust store.",
                style="#B83B5E",
            )
            return
        cert_path, cn = cert_info

        # Confirm the deletion
        answer = qy.confirm(
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
            console.print(
                "[NOTE] You may need to restart your system for the changes to take full effect."
            )
        except subprocess.CalledProcessError as e:
            console.print(f"[ERROR] Failed to remove certificate: {e}", style="#B83B5E")

    else:
        console.print(f"[ERROR] Unsupported platform: {system}", style="#B83B5E")
