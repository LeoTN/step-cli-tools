# --- Standard library imports ---
import platform
import re
from enum import Enum
from pathlib import Path

# --- Third-party imports ---
from rich.panel import Panel

# --- Local application imports ---
from .common import DEFAULT_QY_STYLE, SCRIPT_CERT_DIR, STEP_BIN, console, logger, qy
from .configuration import config
from .data_classes import (
    CertificateRequestInfo,
    CRI_ECCurve,
    CRI_KeyAlgorithm,
    CRI_OKPCurve,
    CRI_OutputFormat,
    CRI_RSAKeySize,
)
from .support_functions_ca import (
    check_ca_health,
    execute_certificate_request,
    get_ca_root_info,
)
from .support_functions_certificates import (
    choose_cert_from_list,
    convert_certificate,
    delete_linux_cert_by_path,
    delete_windows_cert_by_thumbprint,
    find_linux_cert_by_sha256,
    find_linux_certs_by_name,
    find_windows_cert_by_sha256,
    find_windows_certs_by_name,
)
from .support_functions_general import execute_step_command
from .support_functions_paths import join_safe_path
from .validators import (
    CertificateSubjectNameValidator,
    HostnameOrIPAddressAndOptionalPortValidator,
    SHA256OrNameValidator,
    SHA256Validator,
)


def operation1():
    """
    Install a root certificate in the system trust store.

    Prompt the user for the CA server and (optionally) root CA fingerprint, then execute the step-ca bootstrap command.
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
        validate=HostnameOrIPAddressAndOptionalPortValidator,
        style=DEFAULT_QY_STYLE,
    ).ask()

    if not ca_input or not ca_input.strip():
        logger.info("Operation cancelled by user.")
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
            message="Continue with installation of this root CA? (Abort to enter the fingerprint manually)",
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
            logger.info("Operation cancelled by user.")
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
        logger.warning(
            f"Could not check for existing certificates on unsupported platform: {system}"
        )

    # Confirm overwrite
    if cert_info:
        logger.info(
            f"Certificate with fingerprint '{fingerprint}' already exists in the system trust store."
        )
        console.print()
        overwrite_certificate = qy.confirm(
            message="Would you like to overwrite it?",
            default=False,
            style=DEFAULT_QY_STYLE,
        ).ask()
        if not overwrite_certificate:
            logger.info("Operation cancelled by user.")
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
        logger.info(
            "You may need to restart your system for the changes to take full effect."
        )


def operation2():
    """
    Uninstall a root CA certificate from the system trust store.

    Prompt the user for the certificate fingerprint or a search term and remove it from
    the appropriate trust store based on the platform.
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
        logger.info("Operation cancelled by user.")
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
                logger.error(
                    f"No certificate with fingerprint '{fingerprint}' was found in the Windows user ROOT trust store."
                )
                return

        elif search_term:
            certs_info = find_windows_certs_by_name(search_term)
            if not certs_info:
                logger.error(
                    f"No certificates matching '{search_term}' were found in the Windows user ROOT trust store."
                )
                return

            cert_info = (
                choose_cert_from_list(
                    certs_info,
                    "Multiple certificates were found. Please select the one to remove",
                )
                if len(certs_info) > 1
                else certs_info[0]
            )

        if not cert_info:
            logger.info("Operation cancelled by user.")
            return

        thumbprint, cn = cert_info
        delete_windows_cert_by_thumbprint(thumbprint, cn)

    elif system == "Linux":
        if fingerprint:
            cert_info = find_linux_cert_by_sha256(fingerprint)
            if not cert_info:
                logger.error(
                    f"No certificate with fingerprint '{fingerprint}' was found in the Linux trust store."
                )
                return

        elif search_term:
            certs_info = find_linux_certs_by_name(search_term)
            if not certs_info:
                logger.error(
                    f"No certificates matching '{search_term}' were found in the Linux trust store."
                )
                return

            cert_info = (
                choose_cert_from_list(
                    certs_info,
                    "Multiple certificates were found. Please select the one to remove",
                )
                if len(certs_info) > 1
                else certs_info[0]
            )

        if not cert_info:
            logger.info("Operation cancelled by user.")
            return

        cert_path, cn = cert_info
        delete_linux_cert_by_path(cert_path, cn)

    else:
        logger.error(f"Unsupported platform for this operation: {system}")


def operation3():
    """
    Request a new certificate from a step-ca server.

    Prompt the user for various certificate request parameters, request a new certificate and convert it to the desired format.
    """

    def _get_choices(enum_class: type[Enum]) -> list[qy.Choice]:
        """
        Convert an Enum with 'menu_item_name' and 'menu_item_description' into
        a list of questionary.Choice objects for selection prompts.

        Args:
            enum_class: The Enum class to convert.

        Returns:
            List of questionary.Choice objects.
        """
        choices = []
        for item in enum_class:
            # Skip items without a proper name or description
            if getattr(item.value, "menu_item_name", None) and getattr(
                item.value, "menu_item_description", None
            ):
                choices.append(
                    qy.Choice(
                        title=item.value.menu_item_name,
                        description=item.value.menu_item_description,
                        value=item,
                    )
                )
        return choices

    def _prompt_for_password(
        message: str = "Enter password",
        confirm_message: str = "Confirm password",
        max_attempts: int = 10,
    ) -> str | None:
        """
        Prompt the user for a password and confirm it.

        Args:
            message: The message to display to the user.
            confirm_message: The message to display to the user to confirm the password.
            max_attempts: The maximum number of attempts to get a valid password.

        Returns:
            The password if successful, None otherwise.
        """

        for attempt in range(max_attempts):
            password = qy.password(message=message, style=DEFAULT_QY_STYLE).ask()
            if password is None:
                return None  # User cancelled

            confirm = qy.password(message=confirm_message, style=DEFAULT_QY_STYLE).ask()
            if confirm is None:
                return None  # User cancelled

            if password == confirm:
                return password

            # If they don't match, ask if they want to try again
            retry = qy.confirm(
                message=f"Inputs did not match. Try again?",
                style=DEFAULT_QY_STYLE,
            ).ask()
            if not retry:
                return None

        logger.error(f"Failed to get password after {max_attempts} attempts.")
        return None

    # Ask for CA hostname/IP and port
    default = config.get("ca_server_config.default_ca_server")
    console.print()
    ca_input = qy.text(
        message="Enter step CA server hostname or IP (optionally with :port)",
        default=default,
        validate=HostnameOrIPAddressAndOptionalPortValidator,
        style=DEFAULT_QY_STYLE,
    ).ask()

    if not ca_input or not ca_input.strip():
        logger.info("Operation cancelled by user.")
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

    # --- Subject Name ---
    subject_name = qy.text(
        message="Enter subject name",
        validate=CertificateSubjectNameValidator,
        style=DEFAULT_QY_STYLE,
    ).ask()

    if not subject_name or not subject_name.strip():
        logger.info("Operation cancelled by user.")
        return
    subject_name = subject_name.strip()

    # --- Output Format ---
    output_format = qy.select(
        message="Select output format",
        choices=_get_choices(CRI_OutputFormat),
        use_search_filter=True,
        use_jk_keys=False,
        style=DEFAULT_QY_STYLE,
    ).ask()

    if not output_format:
        logger.info("Operation cancelled by user.")
        return

    # The object can now be created because the required parameters have been provided by the user
    cri = CertificateRequestInfo(
        subject_name=subject_name,
        output_format=output_format,
    )

    # --- Optional SAN Entries ---
    while True:
        logger.info(f"SAN Entries: {cri.san_entries}")
        san_entry = qy.text(
            message="Enter additional SAN entry (leave blank to finish)",
            validate=CertificateSubjectNameValidator(accept_blank=True),
            style=DEFAULT_QY_STYLE,
        ).ask()

        if not san_entry or not san_entry.strip():
            break
        san_entry = san_entry.strip()
        cri.san_entries.append(san_entry)

    # --- Key Algorithm ---
    cri.key_algorithm = qy.select(
        message="Select key algorithm",
        choices=_get_choices(CRI_KeyAlgorithm),
        use_search_filter=True,
        use_jk_keys=False,
        style=DEFAULT_QY_STYLE,
    ).ask()

    if not cri.key_algorithm:
        logger.info("Operation cancelled by user.")
        return

    # --- ECC Curve ---
    if cri.is_key_algorithm_ec():
        cri.ecc_curve = qy.select(
            message="Select EC curve",
            choices=_get_choices(CRI_ECCurve),
            use_search_filter=True,
            use_jk_keys=False,
            style=DEFAULT_QY_STYLE,
        ).ask()

        if not cri.ecc_curve:
            logger.info("Operation cancelled by user.")
            return

    # --- RSA Key Size ---
    if cri.is_key_algorithm_rsa():
        cri.rsa_size = qy.select(
            message="Select RSA key size",
            choices=_get_choices(CRI_RSAKeySize),
            use_search_filter=True,
            use_jk_keys=False,
            style=DEFAULT_QY_STYLE,
        ).ask()

        if not cri.rsa_size:
            logger.info("Operation cancelled by user.")
            return

    # --- OKP Curve ---
    if cri.is_key_algorithm_okp():
        # There is only one option at the moment
        cri.okp_curve = CRI_OKPCurve.Ed25519
        """ cri.okp_curve = qy.select(
            message="Select OKP curve",
            choices=_get_choices(CRI_OKPCurve),
            use_search_filter=True,
            use_jk_keys=False,
            style=DEFAULT_QY_STYLE,
        ).ask() """

        if not cri.okp_curve:
            logger.info("Operation cancelled by user.")
            return

    # --- Validity Start Date ---
    # WIP
    # --- Validity End Date ---
    # WIP

    # --- Optional PEM Key Encryption ---
    key_password = None
    if cri.is_output_format_pem():
        key_password = _prompt_for_password(
            message="Enter key password (leave blank for no password)",
            confirm_message="Confirm key password",
        )

    # -- Optional PFX Encryption
    pfx_password = None
    if cri.is_output_format_pfx():
        pfx_password = _prompt_for_password(
            message="Enter PFX password (leave blank for no password)",
            confirm_message="Confirm PFX password",
        )

    result = execute_certificate_request(cri, ca_base_url)
    if not result:
        logger.info("Operation cancelled.")
        return

    crt_path, key_path = result

    try:
        result = convert_certificate(
            crt_path=crt_path,
            key_path=key_path,
            output_dir=Path(SCRIPT_CERT_DIR),
            output_format=cri.output_format,
            key_output_encryption_password=key_password,
            pfx_output_encryption_password=pfx_password,
        )
    except Exception as e:
        logger.error(f"Failed to convert certificate: {e}")
        return

    # Make sure the final output directory exists
    cri.final_output_dir.mkdir(exist_ok=True, parents=True)

    try:
        if result.certificate and result.private_key:
            final_crt_path = join_safe_path(
                target_dir=cri.final_output_dir,
                target_file_name_with_suffix=cri.final_crt_output_name_with_suffix,
            )
            final_key_path = join_safe_path(
                target_dir=cri.final_output_dir,
                target_file_name_with_suffix=cri.final_key_output_name_with_suffix,
            )
            # Move the files to their final destination
            result.certificate.rename(final_crt_path)
            result.private_key.rename(final_key_path)
            logger.info(f"Certificate saved to '{final_crt_path}'.")
            logger.info(f"Private key saved to '{final_key_path}'.")

        elif result.pem_bundle:
            final_pem_bundle_path = join_safe_path(
                target_dir=cri.final_output_dir,
                target_file_name_with_suffix=cri.final_pem_bundle_output_name_with_suffix,
            )
            # Move the file to its final destination
            result.pem_bundle.rename(final_pem_bundle_path)
            logger.info(f"PEM bundle saved to '{final_pem_bundle_path}'.")

        elif result.pfx:
            final_pfx_path = join_safe_path(
                target_dir=cri.final_output_dir,
                target_file_name_with_suffix=cri.final_pfx_bundle_output_name_with_suffix,
            )
            # Move the file to its final destination
            result.pfx.rename(final_pfx_path)
            logger.info(f"PFX saved to '{final_pfx_path}'.")

        # This should never happen but just in case
        else:
            logger.error(
                "Failed to save certificate because of an invalid CertificateConversionResult object."
            )
            return

    except Exception as e:
        logger.error(f"Failed to save certificate: {e}")
        return

    # Delete the key and crt from the cache
    if crt_path.exists():
        try:
            crt_path.unlink()
            logger.debug(f"Deleted certificate '{crt_path}' from cache")
        except Exception as e:
            logger.warning(f"Failed to delete certificate '{crt_path}' from cache: {e}")

    if key_path.exists():
        try:
            key_path.unlink()
            logger.debug(f"Deleted key '{key_path}' from cache")
        except Exception as e:
            logger.warning(f"Failed to delete key '{key_path}' from cache: {e}")
