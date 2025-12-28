# --- Standard library imports ---
import json
import os
import platform
import shutil
import re
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import warnings
from pathlib import Path
from urllib.request import urlopen
from zipfile import ZipFile

# --- Third-party imports ---
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.utils import CryptographyDeprecationWarning
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
    "delete_windows_cert_by_sha256",
    "delete_linux_cert_by_path",
    "choose_cert_from_list",
]


def check_for_update(
    current_version: str, include_prerelease: bool = False
) -> str | None:
    """Check PyPI for newer releases of the package.

    Args:
        current_version: Current version string of the package.
        include_prerelease: Whether to consider pre-release versions.

    Returns:
        The latest version string if a newer version exists, otherwise None.
    """

    pkg = "step-cli-tools"
    cache = Path.home() / f".{pkg}" / ".cache" / "update_check.json"
    cache.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()

    if cache.exists():
        try:
            data = json.loads(cache.read_text())
            latest_version = data.get("latest_version")
            cache_lifetime = int(
                config.get("update_config.check_for_updates_cache_lifetime_seconds")
            )
            if (
                latest_version
                and now - data.get("time", 0) < cache_lifetime
                and version.parse(latest_version) > version.parse(current_version)
            ):
                return latest_version
        except json.JSONDecodeError:
            pass

    try:
        with urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=5) as r:
            data = json.load(r)
            releases = [r for r, files in data["releases"].items() if files]

        if not include_prerelease:
            releases = [r for r in releases if not version.parse(r).is_prerelease]

        if not releases:
            return None

        latest_version = max(releases, key=version.parse)
        cache.write_text(json.dumps({"time": now, "latest_version": latest_version}))

        if version.parse(latest_version) > version.parse(current_version):
            return latest_version

    except Exception:
        return None


def install_step_cli(step_bin: str):
    """Download and install the step CLI binary for the current platform."""

    system = platform.system()
    arch = platform.machine()
    console.print(f"[INFO] Detected platform: {system} {arch}")

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
        console.print(f"[ERROR] Unsupported platform: {system}", style="#B83B5E")
        return

    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, os.path.basename(url))
    console.print(f"[INFO] Downloading step CLI from {url}...")
    with urlopen(url) as response, open(tmp_path, "wb") as out_file:
        out_file.write(response.read())

    console.print(f"[INFO] Extracting {archive_type} archive...")
    if archive_type == "zip":
        with ZipFile(tmp_path, "r") as zip_ref:
            zip_ref.extractall(tmp_dir)
    else:
        with tarfile.open(tmp_path, "r:gz") as tar_ref:
            tar_ref.extractall(tmp_dir)

    step_bin_name = "step.exe" if system == "Windows" else "step"

    # Search recursively for the binary
    matches = []
    for root, dirs, files in os.walk(tmp_dir):
        if step_bin_name in files:
            matches.append(os.path.join(root, step_bin_name))

    if not matches:
        console.print(
            f"[ERROR] Could not find {step_bin_name} in the extracted archive.",
            style="#B83B5E",
        )
        return

    extracted_path = matches[0]  # Take the first found binary

    # Prepare installation path
    binary_dir = os.path.dirname(step_bin)
    os.makedirs(binary_dir, exist_ok=True)

    # Delete old binary if exists
    if os.path.exists(step_bin):
        os.remove(step_bin)

    shutil.move(extracted_path, step_bin)
    os.chmod(step_bin, 0o755)

    console.print(f"[INFO] step CLI installed: {step_bin}")

    try:
        result = subprocess.run([step_bin, "version"], capture_output=True, text=True)
        console.print(f"[INFO] Installed step version:\n{result.stdout.strip()}")
    except Exception as e:
        console.print(f"[ERROR] Failed to run step CLI: {e}", style="#B83B5E")


def execute_step_command(args, step_bin: str, interactive: bool = False):
    """Execute a step CLI command and return output or log errors.

    Args:
        args: List of command arguments to pass to step CLI.
        step_bin: Path to the step binary.
        interactive: If True, run the command interactively without capturing output.

    Returns:
        Command output as a string if successful, otherwise None.
    """

    if not step_bin or not os.path.exists(step_bin):
        console.print(
            "[ERROR] step CLI not found. Please install it first.", style="#B83B5E"
        )
        return None

    try:
        if interactive:
            result = subprocess.run([step_bin] + args)
            if result.returncode != 0:
                console.print(
                    f"[ERROR] step command failed with exit code {result.returncode}",
                    style="#B83B5E",
                )
                return None
            return ""
        else:
            result = subprocess.run([step_bin] + args, capture_output=True, text=True)
            if result.returncode != 0:
                console.print(
                    f"[ERROR] step command failed: {result.stderr.strip()}",
                    style="#B83B5E",
                )
                return None
            return result.stdout.strip()
    except Exception as e:
        console.print(f"[ERROR] Failed to execute step command: {e}", style="#B83B5E")
        return None


def execute_ca_request(
    url: str,
    trust_unknown_default: bool = False,
    timeout: int = 10,
) -> str | None:
    """
    Perform an HTTPS request to the CA, handling untrusted certificates if needed.

    Returns:
        Response body as string, or None on failure or user abort
    """

    def do_request(context):
        with urlopen(url, context=context, timeout=timeout) as response:
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

        if isinstance(reason, ssl.SSLCertVerificationError):
            console.print(
                "[WARNING] Server provided an unknown or self-signed certificate.",
                style="#F9ED69",
            )

            console.print()
            answer = qy.confirm(
                message=f"Do you want to trust '{url}' this time?",
                default=False,
                style=DEFAULT_QY_STYLE,
            ).ask()

            if not answer:
                console.print("[INFO] Operation cancelled by user.")
                return None

            try:
                return do_request(ssl._create_unverified_context())
            except Exception as retry_error:
                console.print(
                    f"[ERROR] Retry failed: {retry_error}\n\nIs the port correct and the server available?",
                    style="#B83B5E",
                )
                return None

        console.print(
            f"[ERROR] Connection failed: {e}\n\nIs the port correct and the server available?",
            style="#B83B5E",
        )
        return None

    except Exception as e:
        console.print(
            f"[ERROR] Request failed: {e}\n\nIs the port correct and the server available?",
            style="#B83B5E",
        )
        return None


def check_ca_health(ca_base_url: str, trust_unknown_default: bool = False) -> bool:
    """Check the health endpoint of a CA server via HTTPS."""

    health_url = ca_base_url.rstrip("/") + "/health"

    response = execute_ca_request(
        health_url,
        trust_unknown_default=trust_unknown_default,
    )

    if response is None:
        return False

    if "ok" in response.lower():
        console.print(f"[INFO] CA at '{ca_base_url}' is healthy.", style="green")
        return True

    console.print(
        f"[ERROR] CA health check failed for '{ca_base_url}'.",
        style="#B83B5E",
    )
    return False


def get_ca_root_info(
    ca_base_url: str,
    trust_unknown_default: bool = False,
) -> CARootInfo | None:
    """
    Fetch the first root certificate from a Smallstep CA and return its name
    and SHA256 fingerprint.

    Args:
        ca_base_url: Base URL of the CA (e.g. https://my-ca-host:9000)
        trust_unknown_default: Skip SSL verification immediately if True

    Returns:
        CARootInfo on success, None on error or user cancel
    """

    roots_url = ca_base_url.rstrip("/") + "/roots.pem"

    pem_bundle = execute_ca_request(
        roots_url,
        trust_unknown_default=trust_unknown_default,
    )

    if pem_bundle is None:
        return None

    try:
        # Extract first PEM certificate
        match = re.search(
            "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            pem_bundle,
            re.S,
        )
        if not match:
            console.print("[ERROR] No certificate found in roots.pem", style="#B83B5E")
            return None

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
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            ca_name = (
                str(cn[0].value)
                if cn and cn[0].value is not None
                else str(cert.subject.rfc4514_string())
            )
        except Exception as e:
            console.print(
                f"[WARNING] Unable to retrieve CA name: {e}",
                style="#F9ED69",
            )
            ca_name = "Unknown CA"

        console.print(
            "[INFO] Root CA information retrieved successfully.",
            style="green",
        )

        return CARootInfo(
            ca_name=ca_name,
            fingerprint_sha256=fingerprint.replace(":", ""),
        )

    except Exception as e:
        console.print(
            f"[ERROR] Failed to process CA root certificate: {e}",
            style="#B83B5E",
        )
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

    if result.returncode != 0:
        console.print(
            f"[ERROR] Failed to query certificates: {result.stderr.strip()}",
            style="#B83B5E",
        )
        return None

    for line in result.stdout.strip().splitlines():
        try:
            obj = json.loads(line)
            if obj["Sha256"].strip().lower() == sha256_fingerprint.lower().replace(
                ":", ""
            ):
                return (obj["Thumbprint"].strip(), obj["Subject"].strip())
        except (ValueError, KeyError, json.JSONDecodeError):
            continue

    return None


def find_windows_certs_by_name(name_pattern: str) -> list[tuple[str, str]]:
    """
    Search Windows user ROOT store for certificates by name.
    Supports simple wildcard '*' and matches separately against
    each component like CN=..., OU=..., O=..., C=...

    Args:
        name_pattern: Name or partial name to search (wildcard * allowed)

    Returns:
        List of tuples (thumbprint, subject) for all matching certificates
    """

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

    if result.returncode != 0:
        console.print(f"[ERROR] Failed to query certificates: {result.stderr.strip()}")
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

            components = [comp.strip() for comp in subject.split(",")]
            for comp in components:
                # Delete leading CN=, O=, OU=, etc.
                match = re.match(r"^(?:CN|O|OU|C|DC)=(.*)$", comp, re.IGNORECASE)
                value = match.group(1).strip() if match else comp
                if pattern_re.match(value):
                    matches.append((thumbprint, subject))
                    break  # Search the next certificate if a match is found

        except (ValueError, KeyError, json.JSONDecodeError):
            continue

    return matches


def find_linux_cert_by_sha256(sha256_fingerprint: str) -> tuple[str, str] | None:
    """
    Search the Linux system trust store for a certificate matching a given SHA256 fingerprint.

    Args:
        sha256_fingerprint: SHA256 fingerprint of the certificate to search for.
                            Can include colons or be in uppercase/lowercase.

    Returns:
        A tuple (path, subject) of the matching certificate if found:
            - path: Full filesystem path to the certificate file in the trust store.
            - subject: Full subject string of the certificate.
        Returns None if no matching certificate is found or if the trust store directory is missing.
    """

    cert_dir = "/etc/ssl/certs"
    fingerprint = sha256_fingerprint.lower().replace(":", "")

    if not os.path.isdir(cert_dir):
        console.print(f"[ERROR] Cert directory not found: {cert_dir}", style="#B83B5E")
        return None

    # Ignore deprecation warnings about non-positive serial numbers
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

        for cert_file in os.listdir(cert_dir):
            path = os.path.join(cert_dir, cert_file)
            if os.path.isfile(path):
                try:
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
                            return (path, cert.subject.rfc4514_string())
                except Exception:
                    continue

    return None


def find_linux_certs_by_name(name_pattern: str) -> list[tuple[str, str]]:
    """
    Search Linux trust store for certificates by name.
    Supports simple wildcard '*' and matches separately against
    each component like CN=..., OU=..., O=..., C=..., DC=...
    Duplicates of the same certificate (e.g. from different files / symlinks) are ignored.

    Args:
        name_pattern: Name or partial name to search (wildcard * allowed)

    Returns:
        List of tuples (path, subject) for all matching certificates
    """

    cert_dir = "/etc/ssl/certs"
    if not os.path.isdir(cert_dir):
        console.print(f"[ERROR] Cert directory not found: {cert_dir}")
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
                    continue
                seen_real_paths.add(real_path)

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
                            matches.append((path, subject_str))
                            break

            except Exception:
                continue

    return matches


def delete_windows_cert_by_sha256(thumbprint: str, cn: str):
    """
    Delete a certificate from the Windows user ROOT store using certutil.

    Args:
        thumbprint: Thumbprint of the certificate to delete.
        cn: Common Name (CN) of the certificate for display purposes.
    """

    console.print()
    answer = qy.confirm(
        message=f"Do you really want to remove the certificate: '{cn}'?",
        default=False,
        style=DEFAULT_QY_STYLE,
    ).ask()
    if not answer:
        console.print("[INFO] Operation cancelled by user.")
        return

    # Validate thumbprint format
    if not re.fullmatch(r"[A-Fa-f0-9]{40}", thumbprint):
        console.print(
            f"[ERROR] Invalid thumbprint format: {thumbprint}", style="#B83B5E"
        )
        return

    delete_cmd = ["certutil", "-delstore", "-user", "ROOT", thumbprint]
    result = subprocess.run(delete_cmd, capture_output=True, text=True)
    if result.returncode == 0:
        console.print(f"[INFO] Certificate '{cn}' removed from Windows ROOT store.")
        console.print(
            "[NOTE] You may need to restart your system for the changes to take full effect."
        )
    else:
        console.print(
            f"[ERROR] Failed to remove certificate: {result.stderr.strip()}",
            style="#B83B5E",
        )


def delete_linux_cert_by_path(cert_path: str, cn: str):
    """
    Delete a certificate from the Linux system trust store.

    Args:
        cert_path: Full path to the certificate symlink in /etc/ssl/certs.
        cn: Common Name (CN) of the certificate for display purposes.
    """

    console.print()
    answer = qy.confirm(
        message=f"Do you really want to remove the certificate: '{cn}'?",
        default=False,
        style=DEFAULT_QY_STYLE,
    ).ask()
    if not answer:
        console.print("[INFO] Operation cancelled by user.")
        return

    try:
        cert_dir = Path("/etc/ssl/certs").resolve()
        source_dir = Path("/usr/local/share/ca-certificates").resolve()

        cert_path_obj = Path(cert_path)

        # Handle symlink target
        if cert_path_obj.is_symlink():
            target_path = cert_path_obj.resolve()

            if target_path.is_relative_to(source_dir):
                subprocess.run(["sudo", "rm", str(target_path)], check=True)
            else:
                console.print(
                    f"[WARNING] Symlink target '{target_path}' is outside {source_dir}, skipping deletion.",
                    style="#F9ED69",
                )

        # Delete the symlink itself if it lives inside /etc/ssl/certs
        if cert_path_obj.parent.resolve().is_relative_to(cert_dir):
            subprocess.run(["sudo", "rm", str(cert_path_obj)], check=True)
        else:
            console.print(
                f"[WARNING] Certificate path '{cert_path_obj}' is outside {cert_dir}, skipping deletion.",
                style="#F9ED69",
            )

        subprocess.run(["sudo", "update-ca-certificates", "--fresh"], check=True)

        console.print(f"[INFO] Certificate '{cn}' removed from Linux trust store.")
        console.print(
            "[NOTE] You may need to restart your system for the changes to take full effect."
        )

    except subprocess.CalledProcessError as e:
        console.print(f"[ERROR] Failed to remove certificate: {e}", style="#B83B5E")


def choose_cert_from_list(
    certs: list[tuple[str, str]], message: str = "Select a certificate:"
) -> tuple[str, str] | None:
    """
    Presents a alphabetically sorted list of certificates to the user and returns the chosen tuple (fingerprint/path, subject).

    Args:
        certs: List of tuples (id, subject) to choose from
        message: message text for the questionary select

    Returns:
        The selected tuple or None if user cancels
    """

    if not certs:
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
        return None

    # Return the full tuple matching the selected subject
    for cert in sorted_certs:
        if cert[1] == selected_subject:
            return cert

    return None
