# --- Standard library imports ---
import base64
import json
import re
import subprocess
import warnings
from pathlib import Path
from typing import TypeVar

# --- Third-party imports ---
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, pkcs12
from cryptography.utils import CryptographyDeprecationWarning

# --- Local application imports ---
from ..common import DEFAULT_QY_STYLE, console, logger, qy
from ..models.data import CertificateConversionResult, CRI_OutputFormat

# Used for the choose_cert_from_list() function
TPathOrStr = TypeVar("TPathOrStr", Path, str)


def find_windows_cert_by_sha256(sha256_fingerprint: str) -> tuple[str, str] | None:
    """
    Search the Windows CurrentUser ROOT certificate store for a certificate matching a given SHA256 fingerprint.

    Args:
        sha256_fingerprint: SHA256 fingerprint of the certificate to search for.
                            Can include colons or be in uppercase/lowercase.

    Returns:
        A tuple (thumbprint, subject) of the matching certificate if found:
            - thumbprint: Certificate thumbprint as used by Windows.
            - subject: Full subject string of the certificate.
        Returns None if no matching certificate is found or if the query fails.
    """

    logger.debug(f"Starting Windows certificate search by SHA256: {sha256_fingerprint}")

    ps_cmd = r"""
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root","CurrentUser"
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    foreach ($cert in $store.Certificates) {
        $bytes = $cert.RawData
        $hash = [System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace "-",""
        [PSCustomObject]@{
            Sha256 = $hash
            Thumbprint = $cert.Thumbprint
            Subject = $cert.Subject
        } | ConvertTo-Json -Compress
    }
    $store.Close()
    """

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    logger.debug(f"PowerShell output: {result.stdout}")
    logger.debug(f"PowerShell stderr: {result.stderr}")
    logger.debug(f"PowerShell exit code: {result.returncode}")

    if result.returncode != 0:
        logger.error(f"Failed to query certificates: {result.stderr.strip()}")
        return

    normalized_fp = sha256_fingerprint.lower().replace(":", "")

    for line in result.stdout.strip().splitlines():
        try:
            obj = json.loads(line)
            logger.debug(f"Processing certificate subject: {obj.get('Subject')}")
            if obj["Sha256"].strip().lower() == normalized_fp:
                logger.debug("Matching certificate found")
                return (obj["Thumbprint"].strip(), obj["Subject"].strip())
        except (ValueError, KeyError, json.JSONDecodeError):
            logger.debug("Skipping invalid or malformed certificate entry")
            continue

    logger.debug("No matching Windows certificate found")
    return


def find_windows_certs_by_name(name_pattern: str) -> list[tuple[str, str]]:
    """
    Search Windows user ROOT store for certificates by name.
    Supports simple wildcard '*' and matches separately against
    each component like CN=..., OU=..., O=..., C=...

    Args:
        name_pattern: Name or partial name to search (wildcard * allowed).

    Returns:
        List of tuples (thumbprint, subject) for all matching certificates.
    """

    logger.debug(f"Starting Windows certificate search by name pattern: {name_pattern}")

    ps_cmd = r"""
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root","CurrentUser"
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    foreach ($cert in $store.Certificates) {
        [PSCustomObject]@{
            Thumbprint = $cert.Thumbprint
            Subject = $cert.Subject
        } | ConvertTo-Json -Compress
    }
    $store.Close()
    """

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    logger.debug(f"PowerShell output: {result.stdout}")
    logger.debug(f"PowerShell stderr: {result.stderr}")
    logger.debug(f"PowerShell exit code: {result.returncode}")

    if result.returncode != 0:
        logger.error(f"Failed to query certificates: {result.stderr.strip()}")
        return []

    # Convert wildcard * to regex
    escaped_pattern = re.escape(name_pattern).replace(r"\*", ".*")
    pattern_re = re.compile(f"^{escaped_pattern}$", re.IGNORECASE)

    matches = []

    for line in result.stdout.strip().splitlines():
        try:
            obj = json.loads(line)
            thumbprint = obj["Thumbprint"].strip()
            subject = obj["Subject"].strip()

            logger.debug(f"Evaluating certificate subject: {subject}")

            components = [comp.strip() for comp in subject.split(",")]
            for comp in components:
                # Delete leading CN=, O=, OU=, etc.
                match = re.match(r"^(?:CN|O|OU|C|DC)=(.*)$", comp, re.IGNORECASE)
                value = match.group(1).strip() if match else comp
                if pattern_re.match(value):
                    logger.debug("Name pattern matched certificate")
                    matches.append((thumbprint, subject))
                    break

        except (ValueError, KeyError, json.JSONDecodeError):
            logger.debug("Skipping invalid or malformed certificate entry")
            continue

    logger.debug(f"Total matching Windows certificates found: {len(matches)}")
    return matches


def find_linux_cert_by_sha256(sha256_fingerprint: str) -> tuple[Path, str] | None:
    """
    Search the Linux system trust store for a certificate matching a given SHA256 fingerprint.

    Args:
        sha256_fingerprint: SHA256 fingerprint of the certificate to search for.
                            Can include colons and may be in uppercase/lowercase.

    Returns:
        A tuple (path, subject) of the matching certificate if found:
            - path: Full filesystem path to the certificate file in the trust store.
            - subject: Full subject string of the certificate.
        Returns None if no matching certificate is found or if the trust store directory is missing.
    """

    logger.debug(f"Starting Linux certificate search by SHA256: {sha256_fingerprint}")

    cert_dir = Path("/etc/ssl/certs")
    fingerprint = sha256_fingerprint.lower().replace(":", "")

    if not cert_dir.is_dir():
        logger.error(f"Cert directory not found: {cert_dir}")
        return

    # Ignore deprecation warnings about non-positive serial numbers
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

        for cert_file in cert_dir.iterdir():
            if cert_file.is_file():
                try:
                    logger.debug(f"Reading certificate file: {cert_file}")
                    cert_data = cert_file.read_bytes()
                    try:
                        # Try PEM first
                        cert = x509.load_pem_x509_certificate(
                            cert_data, default_backend()
                        )
                    except ValueError:
                        # Fallback to DER
                        cert = x509.load_der_x509_certificate(
                            cert_data, default_backend()
                        )
                    fp = cert.fingerprint(hashes.SHA256()).hex()
                    if fp.lower() == fingerprint:
                        logger.debug("Matching Linux certificate found")
                        return cert_file, cert.subject.rfc4514_string()
                except Exception as e:
                    logger.debug(
                        f"Failed to process certificate file '{cert_file}': {e}"
                    )
                    continue

    logger.debug("No matching Linux certificate found")
    return


def find_linux_certs_by_name(name_pattern: str) -> list[tuple[Path, str]]:
    """
    Search Linux trust store for certificates by name.
    Supports simple wildcard '*' and matches separately against
    each component like CN=..., OU=..., O=..., C=..., DC=...
    Duplicates of the same certificate (e.g. from different files / symlinks) are ignored.

    Args:
        name_pattern: Name or partial name to search (wildcard * allowed).

    Returns:
        List of tuples (Path, subject) for all matching certificates.
    """

    logger.debug(f"Starting Linux certificate search by name pattern: {name_pattern}")

    cert_dir = Path("/etc/ssl/certs")
    if not cert_dir.is_dir():
        logger.error(f"Cert directory not found: {cert_dir}")
        return []

    # Convert wildcard * to regex
    escaped_pattern = re.escape(name_pattern).replace(r"\*", ".*")
    pattern_re = re.compile(f"^{escaped_pattern}$", re.IGNORECASE)

    matches: list[tuple[Path, str]] = []
    seen_real_paths: set[Path] = set()

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

        for cert_file in cert_dir.iterdir():
            if not cert_file.is_file():
                continue

            try:
                real_path = cert_file.resolve()

                # Skip duplicate certificates pointing to the same real file
                if real_path in seen_real_paths:
                    logger.debug(f"Skipping duplicate certificate path: {real_path}")
                    continue
                seen_real_paths.add(real_path)

                logger.debug(f"Processing certificate file: {cert_file}")

                cert_data = cert_file.read_bytes()
                try:
                    # PEM support
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                except ValueError:
                    # Fallback to DER
                    cert = x509.load_der_x509_certificate(cert_data, default_backend())

                subject_str = cert.subject.rfc4514_string()
                components = [comp.strip() for comp in subject_str.split(",")]

                for comp in components:
                    match = re.match(r"^(?:CN|O|OU|C|DC)=(.*)$", comp, re.IGNORECASE)
                    value = match.group(1).strip() if match else comp
                    if pattern_re.match(value):
                        logger.debug("Name pattern matched certificate")
                        matches.append((cert_file, subject_str))
                        break

            except Exception as e:
                logger.debug(f"Failed to process certificate file '{cert_file}': {e}")
                continue

    logger.debug(f"Total matching Linux certificates found: {len(matches)}")
    return matches


def delete_windows_cert_by_thumbprint(thumbprint: str, cn: str, elevated: bool = False):
    """
    Delete a certificate from the Windows user ROOT store using PowerShell.

    Args:
        thumbprint: Thumbprint of the certificate to delete.
        cn: Common Name (CN) of the certificate for display purposes.
        elevated: Whether to execute the PowerShell command with elevated privileges.
    """

    logger.debug(locals())

    console.print()
    answer = qy.confirm(
        message=f"Do you really want to remove the certificate '{cn}'?",
        default=False,
        style=DEFAULT_QY_STYLE,
    ).ask()
    if not answer:
        logger.info("Operation cancelled by user.")
        return

    # Validate thumbprint format (SHA-1, 40 hex chars)
    if not re.fullmatch(r"[A-Fa-f0-9]{40}", thumbprint):
        logger.error(f"Invalid thumbprint format: {thumbprint}")
        return

    ps_cmd = f"""
    Import-Module Microsoft.PowerShell.Security -RequiredVersion 3.0.0.0
    $certPath = "Cert:\\CurrentUser\\Root\\{thumbprint}"
    if (-not (Test-Path -Path $certPath)) {{
        exit 1
    }}
    try {{
        Remove-Item -Path $certPath -ErrorAction Stop
        exit 0
    }}
    catch {{
        # Access denied
        if ($_.Exception.NativeErrorCode -eq 5) {{
            exit 2
        }}
        # User cancelled
        if ($_.Exception.NativeErrorCode -eq 1223) {{
            exit 3
        }}
        exit 4
    }}
    """
    ps_cmd_encoded = base64.b64encode(ps_cmd.encode("utf-16le")).decode("ascii")

    if elevated:
        ps_args = [
            "powershell",
            "-NoProfile",
            "-Command",
            # Capture the exit code and pass it through
            f"""
            $proc = Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-EncodedCommand','{ps_cmd_encoded}' -Verb RunAs -Wait -PassThru;
            exit $proc.ExitCode
            """,
        ]
    else:
        ps_args = [
            "powershell",
            "-NoProfile",
            "-EncodedCommand",
            ps_cmd_encoded,
        ]

    logger.debug(f"PowerShell command: {' '.join(ps_args)}")

    result = subprocess.run(
        ps_args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    logger.debug(f"PowerShell output: {result.stdout}")
    logger.debug(f"PowerShell stderr: {result.stderr}")
    logger.debug(f"PowerShell exit code: {result.returncode}")

    if result.returncode == 0:
        logger.info(f"Certificate '{cn}' removed from Windows ROOT store.")
        logger.info(
            "You may need to restart your system for the changes to take full effect."
        )
        return

    if result.returncode == 1:
        logger.warning(f"Certificate '{cn}' not found.")
        return

    # Access denied, offer to retry with elevated privileges
    if result.returncode == 2:
        logger.warning(f"Access denied to remove certificate '{cn}'.")
        console.print()
        retry_with_admin_privileges = qy.confirm(
            message="Retry with elevated privileges?", style=DEFAULT_QY_STYLE
        ).ask()
        if not retry_with_admin_privileges:
            logger.info("Operation cancelled by user.")
            return

        delete_windows_cert_by_thumbprint(thumbprint, cn, elevated=True)
        return

    if result.returncode == 3:
        logger.info("Operation cancelled by user.")
        return

    logger.error(f"Failed to remove certificate with thumbprint '{thumbprint}'")


def delete_linux_cert_by_path(cert_path: Path, cn: str, elevated: bool = False):
    """
    Delete a certificate from the Linux system trust store.

    Args:
        cert_path: Full path to the certificate symlink in /etc/ssl/certs.
        cn: Common Name (CN) of the certificate for display purposes.
        elevated: Whether to execute commands with elevated privileges.
    """

    local_dir = Path("/usr/local/share/ca-certificates").resolve()
    package_dir = Path("/usr/share/ca-certificates").resolve()
    ca_conf_path = Path("/etc/ca-certificates.conf")

    logger.debug(locals())

    def run_cmd(args: list[str], input: str | None = None):
        cmd = ["sudo", *args] if elevated else args
        logger.debug(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            input=input,
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
            errors="replace",
        )
        logger.debug(f"Command output: {result.stdout}")
        logger.debug(f"Command stderr: {result.stderr}")
        logger.debug(f"Command exit code: {result.returncode}")
        return result

    def confirm_retry(message: str) -> bool:
        console.print()
        return qy.confirm(message=message, default=True, style=DEFAULT_QY_STYLE).ask()

    console.print()
    answer = qy.confirm(
        message=f"Do you really want to remove the certificate '{cn}'?",
        default=False,
        style=DEFAULT_QY_STYLE,
    ).ask()
    if not answer:
        logger.info("Operation cancelled by user.")
        return

    if not cert_path.is_symlink():
        logger.warning(f"'{cert_path}' is not a symlink, skipping.")
        return

    target_path = cert_path.resolve()
    logger.debug(f"Resolved symlink target: {target_path}")

    try:
        # Handle local certificates
        if target_path.is_relative_to(local_dir):
            try:
                if not elevated:
                    target_path.touch(exist_ok=True)
            except PermissionError:
                logger.warning(f"No write access to '{target_path}' detected.")
                if confirm_retry("Retry with elevated privileges?"):
                    return delete_linux_cert_by_path(cert_path, cn, elevated=True)
                logger.info("Operation cancelled by user.")
                return
            run_cmd(["rm", str(target_path)])
            logger.info(f"Removed locally installed CA certificate '{cn}'.")

        # Handle package certificates
        elif target_path.is_relative_to(package_dir):
            relative_cert = target_path.relative_to(package_dir)
            logger.debug(f"Certificate originates from package store: {relative_cert}")

            if not ca_conf_path.exists():
                logger.error(f"CA configuration file '{ca_conf_path}' does not exist.")
                return

            try:
                if not elevated:
                    ca_conf_path.touch(exist_ok=True)
            except PermissionError:
                logger.warning(f"No write access to '{ca_conf_path}' detected.")
                if confirm_retry("Retry with elevated privileges?"):
                    return delete_linux_cert_by_path(cert_path, cn, elevated=True)
                logger.info("Operation cancelled by user.")
                return

            # Disable the certificate in the configuration file
            lines = ca_conf_path.read_text(encoding="utf-8").splitlines()
            updated_lines, found, disabled = [], False, False
            for line in lines:
                stripped = line.lstrip("!").strip()
                if stripped == str(relative_cert):
                    found = True
                    if not line.startswith("!"):
                        updated_lines.append(f"!{relative_cert}")
                        disabled = True
                    else:
                        updated_lines.append(line)
                        logger.debug(f"CA '{cn}' already disabled")
                else:
                    updated_lines.append(line)

            if not found:
                logger.warning(
                    f"Certificate '{cn}' not found in '{ca_conf_path}'. It may already be disabled or managed externally."
                )
                return

            backup_path = ca_conf_path.with_suffix(".conf.bak")
            run_cmd(["cp", str(ca_conf_path), str(backup_path)])
            logger.info(f"Backup saved as '{backup_path}'.")
            run_cmd(["tee", str(ca_conf_path)], input="\n".join(updated_lines) + "\n")
            # Show the log message once the file has been updated
            if disabled:
                logger.info(f"Disabled CA '{cn}' in '{ca_conf_path}'.")

        else:
            logger.warning(
                f"Symlink target '{target_path}' is outside known CA source directories, skipping source modification."
            )

        run_cmd(["update-ca-certificates", "--fresh"])
        logger.info(f"Certificate '{cn}' removed from Linux trust store.")
        logger.info(
            "You may need to restart your system for the changes to take full effect."
        )

    except subprocess.CalledProcessError as e:
        logger.debug(f"Command stdout: {e.stdout}")
        logger.debug(f"Command stderr: {e.stderr}")
        if not elevated and confirm_retry("Retry with elevated privileges?"):
            return delete_linux_cert_by_path(cert_path, cn, elevated=True)
        logger.warning(
            f"Could not remove certificate '{cn}'. Operation cancelled."
            if not elevated
            else f"Failed to remove certificate '{cn}'."
        )


def choose_cert_from_list(
    certs: list[tuple[TPathOrStr, str]], message: str = "Select a certificate:"
) -> tuple[TPathOrStr, str] | None:
    """
    Presents an alphabetically sorted list of certificates to the user and returns the chosen tuple (Path/thumbprint, subject).

    Args:
        certs: List of tuples (Path/thumbprint, subject) to choose from.
        message: A message text for the questionary select.

    Returns:
        The selected tuple or None if user cancels.
    """

    logger.debug(f"Presenting certificate selection list with {len(certs)} entries")

    if not certs:
        logger.debug("No certificates available for selection")
        return

    # Sort certificates alphabetically by subject (case-insensitive)
    sorted_certs = sorted(certs, key=lambda cert: cert[1].lower())

    # Extract subjects from the sorted list
    choices = [subject for _, subject in sorted_certs]

    console.print()
    selected_subject = qy.select(
        message=message,
        choices=choices,
        use_search_filter=True,
        use_jk_keys=False,
        style=DEFAULT_QY_STYLE,
    ).ask()

    if selected_subject is None:
        logger.debug("User cancelled certificate selection")
        return

    # Return the full tuple matching the selected subject
    for cert in sorted_certs:
        if cert[1] == selected_subject:
            logger.debug(
                f"User selected a certificate with subject: {selected_subject}"
            )
            return cert

    logger.debug("Selected certificate not found in internal list")
    return


def convert_certificate(
    crt_path: Path,
    key_path: Path,
    output_dir: Path,
    output_format: CRI_OutputFormat,
    key_output_encryption_password: str | None = None,
    pfx_output_encryption_password: str | None = None,
) -> CertificateConversionResult:
    """
    Convert or bundle a CRT and KEY file into the desired output format.

    Args:
        crt_path: Path to the PEM-encoded certificate (.crt).
        key_path: Path to the PEM-encoded private key (.key).
        output_dir: Directory where output file(s) will be written.
        output_format: Desired output format (PEM_CRT_KEY, PEM_BUNDLE, PFX_BUNDLE).
        key_output_encryption_password: Optional password for KEY output.
        pfx_output_encryption_password: Optional password for PFX output.

    Returns:
        CertificateConversionResult with relevant paths set.
    """

    # Mask sensitive values for logging
    debug_locals = {
        key: (
            "***"
            if key
            in {"key_output_encryption_password", "pfx_output_encryption_password"}
            and value is not None
            else value
        )
        for key, value in locals().items()
    }
    logger.debug(debug_locals)

    def _public_key_bytes(public_key: "PublicKeyTypes") -> bytes:
        # Serialize public key to a canonical DER representation for comparison
        return public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    result = CertificateConversionResult(format=output_format)

    # --- PEM_CRT_KEY ---
    if output_format == CRI_OutputFormat.PEM_CRT_KEY:
        crt_out = output_dir / crt_path.name
        key_out = output_dir / key_path.name

        # Copy certificate
        if crt_path != crt_out:
            crt_out.write_bytes(crt_path.read_bytes())
        else:
            logger.debug(
                f"Certificate output path '{crt_out}' is the same as input, skipping copy."
            )

        # Write (optionally encrypted) private key
        if key_output_encryption_password:
            private_key_obj = load_pem_private_key(key_path.read_bytes(), password=None)
            key_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    key_output_encryption_password.encode()
                ),
            )
            key_out.write_bytes(key_bytes)
        else:
            if key_path != key_out:
                key_out.write_bytes(key_path.read_bytes())
            else:
                logger.debug(
                    f"Private key output path '{key_out}' is the same as input, skipping copy."
                )

        result.certificate = crt_out
        result.private_key = key_out
        return result

    crt_data = crt_path.read_bytes()
    key_data = key_path.read_bytes()

    # --- PEM_BUNDLE ---
    if output_format == CRI_OutputFormat.PEM_BUNDLE:
        bundle_path = output_dir / f"{crt_path.stem}_bundle.pem"

        # Encrypt key first if password provided
        if key_output_encryption_password:
            private_key_obj = load_pem_private_key(key_data, password=None)
            key_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    key_output_encryption_password.encode()
                ),
            )
        else:
            key_bytes = key_data

        # Key first, certificate second
        combined = key_bytes.rstrip() + b"\n\n" + crt_data.lstrip()
        bundle_path.write_bytes(combined)

        result.pem_bundle = bundle_path
        return result

    # --- PFX_BUNDLE ---
    if output_format == CRI_OutputFormat.PFX_BUNDLE:
        cert = x509.load_pem_x509_certificate(crt_data)
        private_key = load_pem_private_key(key_data, password=None)

        if not isinstance(
            private_key,
            (
                rsa.RSAPrivateKey,
                dsa.DSAPrivateKey,
                ec.EllipticCurvePrivateKey,
                ed25519.Ed25519PrivateKey,
                ed448.Ed448PrivateKey,
            ),
        ):
            raise TypeError(
                f"Unsupported private key type for PKCS#12 serialization: {type(private_key).__name__}"
            )

        if _public_key_bytes(cert.public_key()) != _public_key_bytes(
            private_key.public_key()
        ):
            raise ValueError(
                f"The provided private key '{key_path}' does not match the certificate '{crt_path}'"
            )

        pfx_path = output_dir / f"{crt_path.stem}.pfx"
        pfx_bytes = pkcs12.serialize_key_and_certificates(
            name=crt_path.stem.encode(),
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=(
                serialization.BestAvailableEncryption(
                    pfx_output_encryption_password.encode()
                )
                if pfx_output_encryption_password
                else serialization.NoEncryption()
            ),
        )
        pfx_path.write_bytes(pfx_bytes)
        result.pfx = pfx_path
        return result

    raise ValueError(f"Unsupported output format: {output_format}")
