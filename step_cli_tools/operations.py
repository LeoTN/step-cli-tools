# --- Standard library imports ---
import platform
import re
from enum import Enum
from pathlib import Path
from typing import TypeVar

# --- Third-party imports ---
from rich.panel import Panel

# --- Local application imports ---
from .common import DEFAULT_QY_STYLE, SCRIPT_CERT_DIR, STEP_BIN, console, logger, qy
from .configuration import config
from .customized_parts_questionary.select import CUSTOMIZED_select
from .data_classes import CertificateRequestInfo, CRI_OutputFormat
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

# Type variable for objects like CRI_OutputFormat, CRI_KeyAlgorithm, etc.
TEnum = TypeVar("TEnum", bound=Enum)


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
            else:
                logger.debug(
                    f"Skipping enum item '{item}' as it lacks property 'menu_item_name' or 'menu_item_description'"
                )
        return choices

    def _select_enum_option(cri_enum_obj: TEnum, message: str) -> TEnum | None:
        """
        Display a questionary select menu for an Enum class (usually CRI_OutputFormat or similar) and return the selected value.

        Args:
            cri_enum_obj: An instance of CRI_OutputFormat or a similar Enum class
            message: Prompt message for the selection

        Returns:
            The selected Enum member, or None if cancelled
        """

        choices = _get_choices(type(cri_enum_obj))
        default_choice = next((c for c in choices if c.value == cri_enum_obj), None)
        console.print()
        selection = CUSTOMIZED_select(
            message=message,
            choices=choices,
            default=default_choice,
            use_search_filter=True,
            use_jk_keys=False,
            style=DEFAULT_QY_STYLE,
        ).ask()
        return selection

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
            console.print()
            password = qy.password(message=message, style=DEFAULT_QY_STYLE).ask()
            if not password:
                return None

            console.print()
            confirm = qy.password(message=confirm_message, style=DEFAULT_QY_STYLE).ask()
            if not confirm:
                return None

            if password == confirm:
                return password

            # If they don't match, ask if they want to try again
            console.print()
            retry = qy.confirm(
                message="Inputs did not match. Try again?",
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
        return

    # Initialize CertificateRequestInfo with default values
    cri = CertificateRequestInfo(
        _subject_name="change.me",
        output_format=CRI_OutputFormat.PEM_CRT_KEY,
    )

    # ----------------------------
    # Start of review/edit section
    # ----------------------------

    def _edit_san_entries(cri_obj: CertificateRequestInfo):
        """
        Allow adding, editing, and removing SAN entries interactively.
        Remembers last selected menu item to restore cursor position.
        """

        last_selected: str | None = None  # Store last selection

        while True:
            san_choices = [
                qy.Choice(
                    title=f"{i + 1}: {v}",
                    value=i,
                    description=(
                        "Automatically derived from subject name and cannot be edited."
                        if i == 0
                        else None
                    ),
                )
                for i, v in enumerate(cri_obj.san_entries)
            ]
            san_choices.append(
                qy.Choice(title="Add", description="Add a new SAN entry.", value="add")
            )
            # Only show "Clear All" if there are multiple entries
            if len(cri_obj.san_entries) > 1:
                san_choices.append(
                    qy.Choice(
                        title="Clear All",
                        description="Clear all additional SAN entries.",
                        value="clear",
                    )
                )
            elif last_selected == "clear":
                # Reset if "Clear All" was last selected but is no longer available
                last_selected = None
            san_choices.append(qy.Choice(title="Save", value="save"))

            console.print()
            choice = CUSTOMIZED_select(
                message="Edit SAN entries",
                choices=san_choices,
                default=last_selected,  # Restore cursor position
                use_search_filter=True,
                use_jk_keys=False,
                style=DEFAULT_QY_STYLE,
            ).ask()

            if not choice or choice == "save":
                return

            # Store last selected value
            last_selected = choice

            if choice == "add":
                console.print()
                new_san = qy.text(
                    message="Enter SAN entry (leave blank to cancel)",
                    validate=CertificateSubjectNameValidator(accept_blank=True),
                    style=DEFAULT_QY_STYLE,
                ).ask()
                if new_san and not new_san.strip() == "":
                    cri_obj.san_entries.append(new_san.strip())

            elif choice == "clear":
                console.print()
                confirm = qy.confirm(
                    message="Clear all SAN entries?",
                    style=DEFAULT_QY_STYLE,
                ).ask()
                if confirm:
                    cri_obj.san_entries.clear()
                    # Re-add subject name to generate default SAN entry
                    cri_obj.subject_name = cri_obj.subject_name

            elif isinstance(choice, int):
                current = cri_obj.san_entries[choice]
                console.print()
                edited = qy.text(
                    message="Edit SAN entry (leave blank to delete)",
                    default=current,
                    validate=CertificateSubjectNameValidator(accept_blank=True),
                    style=DEFAULT_QY_STYLE,
                ).ask()
                # User cancelled (allow empty input for deletion)
                if edited is None:
                    continue

                edited_stripped = edited.strip()
                # Delete if blank
                if edited_stripped == "":
                    cri_obj.san_entries.pop(choice)
                    # Reset last selected if it was deleted
                    if last_selected == choice:
                        last_selected = None
                else:
                    cri_obj.san_entries[choice] = edited_stripped

    def _review_and_edit(cri_obj: CertificateRequestInfo) -> bool:
        """
        Review and optionally edit CertificateRequestInfo fields.
        Remembers last selected position for main menu and submenus
        """

        last_selected_main: str | None = None

        while True:
            # Build main menu
            choices = [
                qy.Choice(
                    title=f"Subject Name: {cri_obj.subject_name}",
                    description="The main subject name for the certificate.",
                    value="subject_name",
                ),
                qy.Choice(
                    title=f"Output Format: {cri_obj.output_format.value.menu_item_name}",
                    description="Output format for the certificate file(s).",
                    value="output_format",
                ),
                qy.Choice(
                    title=f"SAN Entries: {len(cri_obj.san_entries)}",
                    description="The subject alternative names for the certificate.",
                    value="san_entries",
                ),
                qy.Choice(
                    title=f"Key Algorithm: {cri_obj.key_algorithm.value.menu_item_name}",
                    description="The algorithm used for the private key.",
                    value="key_algorithm",
                ),
            ]

            if cri_obj.is_key_algorithm_ec():
                choices.append(
                    qy.Choice(
                        title=f"EC Curve: {cri_obj.ecc_curve.value.menu_item_name}",
                        value="ecc_curve",
                    )
                )
            if cri_obj.is_key_algorithm_rsa():
                choices.append(
                    qy.Choice(
                        title=f"RSA Key Size: {cri_obj.rsa_size.value.menu_item_name}",
                        value="rsa_size",
                    )
                )
            if cri_obj.is_key_algorithm_okp():
                choices.append(
                    qy.Choice(
                        title=f"OKP Curve: {cri_obj.okp_curve.value.menu_item_name}",
                        value="okp_curve",
                    )
                )

            choices.extend(
                [
                    qy.Choice(title="Proceed", value="proceed"),
                    qy.Choice(title="Exit", value="exit"),
                ]
            )

            # Main menu selection
            console.print()
            answer = CUSTOMIZED_select(
                message="Review and edit certificate request",
                choices=choices,
                default=last_selected_main,
                use_search_filter=True,
                use_jk_keys=False,
                style=DEFAULT_QY_STYLE,
            ).ask()

            if answer:
                last_selected_main = answer

            if not answer or answer == "exit":
                logger.info("Operation cancelled by user.")
                return False

            if answer == "proceed":
                try:
                    cri_obj.validate()
                except Exception as e:
                    logger.error(f"Invalid certificate request configuration: {e}")
                    continue
                return True

            # Submenu: Subject Name
            if answer == "subject_name":
                console.print()
                value = qy.text(
                    message="Enter subject name",
                    default=cri_obj.subject_name,
                    validate=CertificateSubjectNameValidator,
                    style=DEFAULT_QY_STYLE,
                ).ask()
                if value:
                    cri_obj.subject_name = value.strip()

            # Submenu: Output Format
            elif answer == "output_format":
                value = _select_enum_option(
                    cri_obj.output_format, "Select output format"
                )
                if value:
                    cri_obj.output_format = value

            # Submenu: Validity
            # WIP

            # Submenu: SAN Entries
            elif answer == "san_entries":
                _edit_san_entries(cri_obj)

            # Submenu: Key Algorithm
            elif answer == "key_algorithm":
                value = _select_enum_option(
                    cri_obj.key_algorithm, "Select key algorithm"
                )
                if value:
                    cri_obj.key_algorithm = value

            # Submenu: EC Curve
            elif answer == "ecc_curve" and cri_obj.is_key_algorithm_ec():
                value = _select_enum_option(cri_obj.ecc_curve, "Select EC curve")
                if value:
                    cri_obj.ecc_curve = value

            # Submenu: RSA Size
            elif answer == "rsa_size" and cri_obj.is_key_algorithm_rsa():
                value = _select_enum_option(cri_obj.rsa_size, "Select RSA key size")
                if value:
                    cri_obj.rsa_size = value

            # Submenu: OKP Curve
            elif answer == "okp_curve" and cri_obj.is_key_algorithm_okp():
                value = _select_enum_option(cri_obj.okp_curve, "Select OKP curve")
                if value:
                    cri_obj.okp_curve = value

    proceed = _review_and_edit(cri)
    if not proceed:
        return

    # After finalizing options, ask for optional key password depending on output format
    key_password = None
    if cri.is_output_format_pem():
        key_password = _prompt_for_password(
            message="Enter key password (leave blank for no password)",
            confirm_message="Confirm key password",
        )

    # Optional PFX Encryption
    pfx_password = None
    if cri.is_output_format_pfx():
        pfx_password = _prompt_for_password(
            message="Enter PFX password (leave blank for no password)",
            confirm_message="Confirm PFX password",
        )

    # --------------------------
    # End of review/edit section
    # --------------------------

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
