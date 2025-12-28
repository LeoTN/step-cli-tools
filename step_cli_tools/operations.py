# --- Standard library imports ---
import platform
import re

# --- Third-party imports ---
from rich.panel import Panel


# --- Local application imports ---
from .common import *
from .configuration import *
from .support_functions import *
from .validators import *

__all__ = [
    "operation1",
    "operation2",
]


def operation1():
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
        "Make sure you fully [bold]trust the CA before proceeding![/bold]"
    )
    console.print(Panel.fit(warning_text, title="WARNING", border_style="#F9ED69"))

    # Ask for CA hostname/IP and port
    default = config.get("ca_server_config.default_ca_server")
    console.print()
    ca_input = qy.text(
        message="Enter step CA server hostname or IP (optionally with :port)",
        default=default,
        validate=HostnamePortValidator,
        style=DEFAULT_QY_STYLE,
    ).ask()

    if not ca_input or not ca_input.strip():
        console.print("[INFO] Operation cancelled by user.")
        return

    # Parse host and port
    ca_server, _, port_str = ca_input.partition(":")
    port = int(port_str) if port_str else 9000
    ca_base_url = f"https://{ca_server}:{port}"

    # Run the health check via helper
    trust_unknown_default = config.get(
        "ca_server_config.trust_unknow_certificates_by_default"
    )
    if not check_ca_health(ca_base_url, trust_unknown_default):
        # Either failed or user cancelled
        return

    use_fingerprint = False
    if config.get("ca_server_config.fetch_root_ca_certificate_automatically"):
        # Get root certificate info
        ca_root_info = get_ca_root_info(ca_base_url, trust_unknown_default)
        if ca_root_info is None:
            return

        # Display the CA information
        info_text = (
            f"[bold]Name:[/bold] {ca_root_info.ca_name}\n"
            f"[bold]SHA256 Fingerprint:[/bold] {ca_root_info.fingerprint_sha256}"
        )
        console.print(
            Panel.fit(info_text, title="CA Information", border_style="#F08A5D")
        )

        # Ask the user if they would like to use this fingerprint or enter it manually
        console.print()
        use_fingerprint = qy.confirm(
            message=f"Continue with installation of this root CA? (Abort to enter the fingerprint manually)",
            style=DEFAULT_QY_STYLE,
        ).ask()

    if use_fingerprint:
        fingerprint = ca_root_info.fingerprint_sha256
    else:
        # Ask for fingerprint
        console.print()
        fingerprint = qy.text(
            message="Enter root certificate fingerprint (SHA256, 64 hex chars)",
            validate=SHA256Validator,
            style=DEFAULT_QY_STYLE,
        ).ask()
        # Check for empty input
        if not fingerprint or not fingerprint.strip():
            console.print("[INFO] Operation cancelled by user.")
            return
    # step-cli expects the fingerprint without colons
    fingerprint = fingerprint.replace(":", "")

    # Check if the certificate is already installed
    system = platform.system()
    cert_info = None

    if system == "Windows":
        cert_info = find_windows_cert_by_sha256(fingerprint)
    elif system == "Linux":
        cert_info = find_linux_cert_by_sha256(fingerprint)
    else:
        console.print(
            f"[WARNING] Could not check for existing certificates on unsupported platform: {system}",
            style="#F9ED69",
        )
    # Confirm overwrite
    if cert_info:
        console.print(
            f"[INFO] Certificate with fingerprint '{fingerprint}' already exists in the system trust store.",
            style="#F08A5D",
        )
        console.print()
        overwrite_certificate = qy.confirm(
            message="Would you like to overwrite it?",
            default=False,
            style=DEFAULT_QY_STYLE,
        ).ask()
        if not overwrite_certificate:
            console.print("[INFO] Operation cancelled by user.")
            return

    # Run step-ca bootstrap
    bootstrap_args = [
        "ca",
        "bootstrap",
        "--ca-url",
        ca_base_url,
        "--fingerprint",
        fingerprint,
        "--install",
        "--force",
    ]

    result = execute_step_command(bootstrap_args, STEP_BIN)
    if isinstance(result, str):
        console.print(
            "[NOTE] You may need to restart your system for the changes to take full effect."
        )


def operation2():
    """
    Uninstall a root CA certificate from the system trust store.

    Prompts the user for the certificate fingerprint or a search term and removes it from
    the appropriate trust store based on the platform.

    Returns:
        None
    """

    warning_text = (
        "You are about to remove a root CA certificate from your system.\n"
        "This is a sensitive operation and can affect [bold]system security[/bold].\n"
        "Proceed only if you know what you are doing!"
    )
    console.print(Panel.fit(warning_text, title="WARNING", border_style="#F9ED69"))

    # Ask for the fingerprint or a search term
    console.print()
    fingerprint_or_search_term = qy.text(
        message="Enter root certificate fingerprint (SHA256, 64 hex chars) or search term (* wildcards allowed)",
        validate=SHA256OrNameValidator,
        style=DEFAULT_QY_STYLE,
    ).ask()

    # Check for empty input
    if not fingerprint_or_search_term or not fingerprint_or_search_term.strip():
        console.print("[INFO] Operation cancelled by user.")
        return
    fingerprint_or_search_term = fingerprint_or_search_term.replace(":", "").strip()

    # Define if the input is a fingerprint or a search term
    fingerprint = None
    search_term = None
    if re.fullmatch(r"[A-Fa-f0-9]{64}", fingerprint_or_search_term):
        fingerprint = fingerprint_or_search_term
    else:
        search_term = fingerprint_or_search_term

    # Determine platform
    system = platform.system()
    cert_info = None

    if system == "Windows":
        if fingerprint:
            cert_info = find_windows_cert_by_sha256(fingerprint)
            if not cert_info:
                console.print(
                    f"[ERROR] No certificate with fingerprint '{fingerprint}' was found in the Windows user ROOT trust store.",
                    style="#B83B5E",
                )
                return

        elif search_term:
            certs_info = find_windows_certs_by_name(search_term)
            if not certs_info:
                console.print(
                    f"[ERROR] No certificates matching '{search_term}' were found in the Windows user ROOT trust store.",
                    style="#B83B5E",
                )
                return

            cert_info = (
                choose_cert_from_list(
                    certs_info,
                    "Multiple certificates were found. Please select the one to remove:",
                )
                if len(certs_info) > 1
                else certs_info[0]
            )

        if not cert_info:
            console.print("[INFO] Operation cancelled by user.")
            return

        thumbprint, cn = cert_info
        delete_windows_cert_by_sha256(thumbprint, cn)

    elif system == "Linux":
        if fingerprint:
            cert_info = find_linux_cert_by_sha256(fingerprint)
            if not cert_info:
                console.print(
                    f"[ERROR] No certificate with fingerprint '{fingerprint}' was found in the Linux trust store.",
                    style="#B83B5E",
                )
                return

        elif search_term:
            certs_info = find_linux_certs_by_name(search_term)
            if not certs_info:
                console.print(
                    f"[ERROR] No certificates matching '{search_term}' were found in the Linux trust store.",
                    style="#B83B5E",
                )
                return

            cert_info = (
                choose_cert_from_list(
                    certs_info,
                    "Multiple certificates were found. Please select the one to remove:",
                )
                if len(certs_info) > 1
                else certs_info[0]
            )

        if not cert_info:
            console.print("[INFO] Operation cancelled by user.")
            return

        cert_path, cn = cert_info
        delete_linux_cert_by_path(cert_path, cn)

    else:
        console.print(
            f"[ERROR] Unsupported platform for this operation: {system}",
            style="#B83B5E",
        )
