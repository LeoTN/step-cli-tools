# --- Standard library imports ---
import base64
import json
import os
import platform
import re
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import time
import warnings
from pathlib import Path
from urllib.request import urlopen
import urllib.error
from zipfile import ZipFile

# --- Third-party imports ---
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import NameOID
from packaging import version

# --- Local application imports ---
from .common import *
from .configuration import *
from .data_classes import *

__all__ = [
    "check_for_update",
    "install_step_cli",
    "execute_step_command",
    "check_ca_health",
    "get_ca_root_info",
    "find_windows_cert_by_sha256",
    "find_windows_certs_by_name",
    "find_linux_cert_by_sha256",
    "find_linux_certs_by_name",
    "delete_windows_cert_by_thumbprint",
    "delete_linux_cert_by_path",
    "choose_cert_from_list",
]


def check_for_update(
    pkg_name: str, current_pkg_version: str, include_prerelease: bool = False
) -> str | None:
    """
    Check PyPI for newer releases of the package.

    Args:
        pkg_name: Name of the package.
        current_pkg_version: Current version string of the package.
        include_prerelease: Whether to consider pre-release versions.

    Returns:
        The latest version string if a newer version exists, otherwise None.
    """

    cache = Path.home() / f".{pkg_name}" / ".cache" / "update_check.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    current_parsed_version = version.parse(current_pkg_version)

    logger.debug(locals())

    # Try reading from cache
    if cache.exists():
        try:
            with cache.open("r", encoding="utf-8") as file:
                data = json.load(file)

            latest_version = data.get("latest_version")
            cache_lifetime = int(
                config.get("update_config.check_for_updates_cache_lifetime_seconds")
            )

            if (
                latest_version
                and now - data.get("time", 0) < cache_lifetime
                and version.parse(latest_version) > current_parsed_version
            ):
                logger.debug("Returning newer version from cache")
                return latest_version

        except (json.JSONDecodeError, OSError) as e:
            logger.debug(f"Failed to read update cache: {e}")

    # Fetch the latest releases from PyPI when the cache is empty, expired, or the cached version is older than the current version
    try:
        logger.debug("Fetching release metadata from PyPI")
        with urlopen(f"https://pypi.org/pypi/{pkg_name}/json", timeout=5) as response:
            data = json.load(response)

        # Filter releases (exclude ones with yanked files)
        releases = [
            ver
            for ver, files in data["releases"].items()
            if files and all(not file.get("yanked", False) for file in files)
        ]

        # Exclude pre-releases if not requested
        if not include_prerelease:
            releases = [r for r in releases if not version.parse(r).is_prerelease]

        if not releases:
            logger.debug("No valid releases found")
            return None

        latest_version = max(releases, key=version.parse)
        latest_parsed_version = version.parse(latest_version)

        logger.debug(f"Latest available version on PyPI: {latest_version}")

        # Write cache
        try:
            with cache.open("w", encoding="utf-8") as file:
                json.dump({"time": now, "latest_version": latest_version}, file)
        except OSError as e:
            logger.debug(f"Failed to write update cache: {e}")

        if latest_parsed_version > current_parsed_version:
            logger.debug(f"Update available: {latest_version}")
            return latest_version

    except Exception as e:
        logger.debug(f"Update check failed: {e}")
        return None


def install_step_cli(step_bin: str):
    """
    Download and install the step-cli binary for the current platform.

    Args:
        step_bin: Path to the step binary.
    """

    system = platform.system()
    arch = platform.machine()
    logger.info(f"Detected platform: {system} {arch}")
    logger.info(f"Target installation path: {step_bin}")

    if system == "Windows":
        url = "https://github.com/smallstep/cli/releases/latest/download/step_windows_amd64.zip"
        archive_type = "zip"
    elif system == "Linux":
        url = "https://github.com/smallstep/cli/releases/latest/download/step_linux_amd64.tar.gz"
        archive_type = "tar.gz"
    elif system == "Darwin":
        url = "https://github.com/smallstep/cli/releases/latest/download/step_darwin_amd64.tar.gz"
        archive_type = "tar.gz"
    else:
        logger.error(f"Unsupported platform: {system}")
        return

    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, os.path.basename(url))
    logger.info(f"Downloading step-cli from '{url}'...")

    with urlopen(url) as response, open(tmp_path, "wb") as out_file:
        out_file.write(response.read())

    logger.debug(f"Archive downloaded to temporary path: {tmp_path}")

    logger.info(f"Extracting '{archive_type}' archive...")
    if archive_type == "zip":
        with ZipFile(tmp_path, "r") as zip_ref:
            zip_ref.extractall(tmp_dir)
    else:
        with tarfile.open(tmp_path, "r:gz") as tar_ref:
            tar_ref.extractall(tmp_dir)

    step_bin_name = os.path.basename(step_bin)

    # Search recursively for the binary
    matches = []
    for root, _, files in os.walk(tmp_dir):
        if step_bin_name in files:
            found_path = os.path.join(root, step_bin_name)
            matches.append(found_path)

    if not matches:
        logger.error(f"Could not find '{step_bin_name}' in the extracted archive.")
        return

    extracted_path = matches[0]  # Take the first found binary
    logger.debug(f"Using extracted binary: {extracted_path}")

    # Prepare installation path
    binary_dir = os.path.dirname(step_bin)
    os.makedirs(binary_dir, exist_ok=True)

    # Delete old binary if exists
    if os.path.exists(step_bin):
        logger.debug("Removing existing step binary")
        os.remove(step_bin)

    shutil.move(extracted_path, step_bin)
    os.chmod(step_bin, 0o755)

    logger.info(f"step-cli installed: {step_bin}")

    try:
        result = subprocess.run([step_bin, "version"], capture_output=True, text=True)
        logger.info(f"Installed step version:\n{result.stdout.strip()}")
    except Exception as e:
        logger.error(f"Failed to run step-cli: {e}")


def execute_step_command(args, step_bin: str, interactive: bool = False) -> str | None:
    """
    Execute a step-cli command and return output or log errors.

    Args:
        args: List of command arguments to pass to step-cli.
        step_bin: Path to the step binary.
        interactive: If True, run the command interactively without capturing output.

    Returns:
        Command output as a string if successful, otherwise None.
    """

    logger.debug(locals())

    if not step_bin or not os.path.exists(step_bin):
        logger.error("step-cli not found. Please install it first.")
        return None

    try:
        if interactive:
            result = subprocess.run([step_bin] + args)
            logger.debug(f"step-cli command exit code: {result.returncode}")

            if result.returncode != 0:
                logger.error(f"step-cli command exit code: {result.returncode}")
                return None

            return ""
        else:
            result = subprocess.run([step_bin] + args, capture_output=True, text=True)
            logger.debug(f"step-cli command exit code: {result.returncode}")

            if result.returncode != 0:
                logger.error(f"step-cli command failed: {result.stderr.strip()}")
                return None

            return result.stdout.strip()

    except Exception as e:
        logger.error(f"Failed to execute step-cli command: {e}")
        return None


def execute_ca_request(
    url: str,
    trust_unknown_default: bool = False,
    timeout: int = 10,
) -> str | None:
    """
    Perform an HTTPS request to the CA, handling untrusted certificates if needed.

    Args:
        url: URL to request.
        trust_unknown_default: If True, trust unverified SSL certificates.
        timeout: Timeout in seconds.

    Returns:
        Response body as string, or None on failure or user abort.
    """

    logger.debug(locals())

    def do_request(context):
        with urlopen(url, context=context, timeout=timeout) as response:
            logger.debug(f"Received HTTP response status code: {response.status}")
            return response.read().decode("utf-8").strip()

    context = (
        ssl._create_unverified_context()
        if trust_unknown_default
        else ssl.create_default_context()
    )

    try:
        return do_request(context)

    except urllib.error.URLError as e:
        reason = getattr(e, "reason", None)

        logger.debug(f"URLError: {e}")

        if isinstance(reason, ssl.SSLCertVerificationError):
            logger.warning("Server provided an unknown or self-signed certificate.")

            console.print()
            answer = qy.confirm(
                message=f"Do you want to trust '{url}' this time?",
                default=False,
                style=DEFAULT_QY_STYLE,
            ).ask()

            if not answer:
                logger.info("Operation cancelled by user.")
                return None

            logger.debug("Retrying request with unverified SSL context")

            try:
                return do_request(ssl._create_unverified_context())
            except Exception as retry_error:
                logger.error(
                    f"Retry failed: {retry_error}\n\nIs the port correct and the server available?"
                )
                return None

        logger.error(
            f"Connection failed: {e}\n\nIs the port correct and the server available?"
        )
        return None

    except Exception as e:
        logger.error(
            f"Request failed: {e}\n\nIs the port correct and the server available?"
        )
        return None


def check_ca_health(ca_base_url: str, trust_unknown_default: bool = False) -> bool:
    """
    Check the health endpoint of a CA server via HTTPS.

    Args:
        ca_base_url: Base URL of the CA server, including protocol and port.
        trust_unknown_default: If True, trust unverified SSL certificates.

    Returns:
        True if the CA is healthy, False otherwise.
    """

    logger.debug(locals())

    health_url = ca_base_url.rstrip("/") + "/health"

    response = execute_ca_request(
        health_url,
        trust_unknown_default=trust_unknown_default,
    )

    if response is None:
        logger.debug("CA health check failed due to missing response")
        return False

    logger.debug(f"Health endpoint response: {response}")

    if "ok" in response.lower():
        logger.info(f"CA at '{ca_base_url}' is healthy.")
        return True

    logger.error(f"CA health check failed for '{ca_base_url}'.")
    return False


def get_ca_root_info(
    ca_base_url: str,
    trust_unknown_default: bool = False,
) -> CARootInfo | None:
    """
    Fetch the first root certificate from a Smallstep CA and return its name
    and SHA256 fingerprint.

    Args:
        ca_base_url: Base URL of the CA (e.g. https://my-ca-host:9000).
        trust_unknown_default: Skip SSL verification immediately if True.

    Returns:
        CARootInfo on success, None on error or user cancel.
    """

    logger.debug(locals())

    roots_url = ca_base_url.rstrip("/") + "/roots.pem"

    pem_bundle = execute_ca_request(
        roots_url,
        trust_unknown_default=trust_unknown_default,
    )

    if pem_bundle is None:
        logger.debug("Failed to retrieve roots.pem")
        return None

    try:
        # Extract first PEM certificate
        match = re.search(
            "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            pem_bundle,
            re.S,
        )
        if not match:
            logger.error("No certificate found in roots.pem")
            return None

        logger.debug("Loading PEM certificate")
        cert = x509.load_pem_x509_certificate(
            match.group(0).encode(),
            default_backend(),
        )

        # Compute SHA256 fingerprint
        fingerprint_hex = cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint = ":".join(
            fingerprint_hex[i : i + 2] for i in range(0, len(fingerprint_hex), 2)
        )

        # Extract CA name (CN preferred, always string)
        logger.debug(f"Computed SHA256 fingerprint: {fingerprint}")

        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            ca_name = (
                str(cn[0].value)
                if cn and cn[0].value is not None
                else str(cert.subject.rfc4514_string())
            )
        except Exception as e:
            logger.warning(f"Unable to retrieve CA name: {e}")
            ca_name = "Unknown CA"

        logger.info("Root CA information retrieved successfully.")

        return CARootInfo(
            ca_name=ca_name,
            fingerprint_sha256=fingerprint.replace(":", ""),
        )

    except Exception as e:
        logger.error(f"Failed to process CA root certificate: {e}")
        return None


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
        return None

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
    return None


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


def find_linux_cert_by_sha256(sha256_fingerprint: str) -> tuple[str, str] | None:
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

    cert_dir = "/etc/ssl/certs"
    fingerprint = sha256_fingerprint.lower().replace(":", "")

    if not os.path.isdir(cert_dir):
        logger.error(f"Cert directory not found: {cert_dir}")
        return None

    # Ignore deprecation warnings about non-positive serial numbers
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

        for cert_file in os.listdir(cert_dir):
            path = os.path.join(cert_dir, cert_file)
            if os.path.isfile(path):
                try:
                    logger.debug(f"Reading certificate file: {path}")
                    with open(path, "rb") as f:
                        cert_data = f.read()
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
                            return (path, cert.subject.rfc4514_string())
                except Exception as e:
                    logger.debug(f"Failed to process certificate file '{path}': {e}")
                    continue

    logger.debug("No matching Linux certificate found")
    return None


def find_linux_certs_by_name(name_pattern: str) -> list[tuple[str, str]]:
    """
    Search Linux trust store for certificates by name.
    Supports simple wildcard '*' and matches separately against
    each component like CN=..., OU=..., O=..., C=..., DC=...
    Duplicates of the same certificate (e.g. from different files / symlinks) are ignored.

    Args:
        name_pattern: Name or partial name to search (wildcard * allowed).

    Returns:
        List of tuples (path, subject) for all matching certificates.
    """

    logger.debug(f"Starting Linux certificate search by name pattern: {name_pattern}")

    cert_dir = "/etc/ssl/certs"
    if not os.path.isdir(cert_dir):
        logger.error(f"Cert directory not found: {cert_dir}")
        return []

    # Convert wildcard * to regex
    escaped_pattern = re.escape(name_pattern).replace(r"\*", ".*")
    pattern_re = re.compile(f"^{escaped_pattern}$", re.IGNORECASE)

    matches = []
    seen_real_paths: set[str] = set()

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

        for cert_file in os.listdir(cert_dir):
            path = os.path.join(cert_dir, cert_file)
            if not os.path.isfile(path):
                continue

            try:
                real_path = os.path.realpath(path)

                # Skip duplicate certificates pointing to the same real file
                if real_path in seen_real_paths:
                    logger.debug(f"Skipping duplicate certificate path: {real_path}")
                    continue
                seen_real_paths.add(real_path)

                logger.debug(f"Processing certificate file: {path}")

                with open(path, "rb") as f:
                    cert_data = f.read()
                    try:
                        # PEM support
                        cert = x509.load_pem_x509_certificate(
                            cert_data, default_backend()
                        )
                    except ValueError:
                        # Fallback to DER
                        cert = x509.load_der_x509_certificate(
                            cert_data, default_backend()
                        )
                    subject_str = cert.subject.rfc4514_string()
                    components = [comp.strip() for comp in subject_str.split(",")]

                    for comp in components:
                        match = re.match(
                            r"^(?:CN|O|OU|C|DC)=(.*)$", comp, re.IGNORECASE
                        )
                        value = match.group(1).strip() if match else comp
                        if pattern_re.match(value):
                            logger.debug("Name pattern matched certificate")
                            matches.append((path, subject_str))
                            break

            except Exception as e:
                logger.debug(f"Failed to process certificate file '{path}': {e}")
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
        message=f"Do you really want to remove the certificate: '{cn}'?",
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
            return None

        delete_windows_cert_by_thumbprint(thumbprint, cn, elevated=True)
        return

    if result.returncode == 3:
        logger.info("Operation cancelled by user.")
        return

    logger.error(f"Failed to remove certificate with thumbprint '{thumbprint}'")


def delete_linux_cert_by_path(cert_path: str, cn: str, elevated: bool = False):
    """
    Delete a certificate from the Linux system trust store.

    Args:
        cert_path: Full path to the certificate symlink in /etc/ssl/certs.
        cn: Common Name (CN) of the certificate for display purposes.
        elevated: Whether to execute commands with elevated privileges.
    """

    cert_path_obj = Path(cert_path)
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
        message=f"Do you really want to remove the certificate: '{cn}'?",
        default=False,
        style=DEFAULT_QY_STYLE,
    ).ask()
    if not answer:
        logger.info("Operation cancelled by user.")
        return

    if not cert_path_obj.is_symlink():
        logger.warning(f"'{cert_path}' is not a symlink, skipping.")
        return

    target_path = cert_path_obj.resolve()
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
    certs: list[tuple[str, str]], message: str = "Select a certificate:"
) -> tuple[str, str] | None:
    """
    Presents an alphabetically sorted list of certificates to the user and returns the chosen tuple (fingerprint/path, subject).

    Args:
        certs: List of tuples (id, subject) to choose from.
        message: message text for the questionary select.

    Returns:
        The selected tuple or None if user cancels.
    """

    logger.debug(f"Presenting certificate selection list with {len(certs)} entries")

    if not certs:
        logger.debug("No certificates available for selection")
        return None

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
        return None

    # Return the full tuple matching the selected subject
    for cert in sorted_certs:
        if cert[1] == selected_subject:
            logger.debug(
                f"User selected a certificate with subject: {selected_subject}"
            )
            return cert

    logger.debug("Selected certificate not found in internal list")
    return None
