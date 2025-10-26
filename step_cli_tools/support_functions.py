# --- Standard library imports ---
import json
import os
import platform
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.request import urlopen
from zipfile import ZipFile
import warnings

# --- Third-party imports ---
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.utils import CryptographyDeprecationWarning
from packaging import version

# --- Local application imports ---
from .common import *
from .configuration import *

__all__ = [
    "ask_boolean_question",
    "check_for_update",
    "install_step_cli",
    "execute_step_command",
    "check_ca_health",
    "find_windows_cert_by_sha256",
    "find_linux_cert_by_sha256",
]


def ask_boolean_question(prompt_text: str) -> bool:
    """Prompt the user with a yes/no question and return a boolean response."""
    while True:
        response = input(f"{prompt_text} (y/n): ").strip().lower()
        if response == "y":
            return True
        elif response == "n":
            return False
        else:
            console.print(
                "[ERROR] Invalid input. Please enter 'y' or 'n'.", style="#B83B5E"
            )


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
        context = ssl.create_default_context()
        with urlopen(
            f"https://pypi.org/pypi/{pkg}/json", timeout=5, context=context
        ) as r:
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
    context = ssl.create_default_context()
    with urlopen(url, context=context) as response, open(tmp_path, "wb") as out_file:
        out_file.write(response.read())

    console.print(f"[INFO] Extracting {archive_type} archive...")
    if archive_type == "zip":
        with ZipFile(tmp_path, "r") as zip_ref:
            zip_ref.extractall(tmp_dir)
    else:
        with tarfile.open(tmp_path, "r:gz") as tar_ref:
            tar_ref.extractall(tmp_dir)

    step_bin_name = "step.exe" if system == "Windows" else "step"
    extracted_path = os.path.join(tmp_dir, step_bin_name)
    if not os.path.exists(extracted_path):
        for root, dirs, files in os.walk(tmp_dir):
            if step_bin_name in files:
                extracted_path = os.path.join(root, step_bin_name)
                break

    binary_dir = os.path.dirname(step_bin)
    os.makedirs(binary_dir, exist_ok=True)
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


def check_ca_health(ca_url: str, trust_unknown_default: bool = False) -> bool:
    """Check the health endpoint of a CA server via HTTPS.

    Args:
        ca_url: URL to the CA health endpoint.
        trust_unknown_default: Skip SSL verification immediately if True.

    Returns:
        True if CA responds "ok", False otherwise.
    """

    def do_request(context):
        with urlopen(ca_url, context=context, timeout=10) as r:
            return "ok" in r.read().decode("utf-8").strip().lower()

    # Select SSL context
    context = (
        ssl._create_unverified_context()
        if trust_unknown_default
        else ssl.create_default_context()
    )

    try:
        if do_request(context):
            console.print(f"[INFO] CA at {ca_url} is healthy.", style="green")
            return True
        console.print(f"[ERROR] CA health check failed for {ca_url}.", style="#B83B5E")
        return False

    except urllib.error.URLError as e:
        reason = getattr(e, "reason", None)
        # Handle SSL certificate errors
        if isinstance(reason, ssl.SSLCertVerificationError):
            console.print(
                "[WARNING] Server provided an unknown or untrusted certificate.",
                style="#F9ED69",
            )
            answer = qy.confirm(
                f"Do you really want to trust '{ca_url}'?",
                style=DEFAULT_QY_STYLE,
                default=False,
            ).ask()
            if not answer:
                console.print("[INFO] Operation cancelled by user.")
                return False
            try:
                if do_request(ssl._create_unverified_context()):
                    console.print(f"[INFO] CA at {ca_url} is healthy.", style="green")
                    return True
                console.print(
                    f"[ERROR] CA health check failed for {ca_url}.", style="#B83B5E"
                )
                return False
            except Exception as e2:
                console.print(f"[ERROR] Retry failed: {e2}", style="#B83B5E")
                return False

        console.print(
            f"[ERROR] Connection failed: {e}\n\nIs the port correct and the server available?",
            style="#B83B5E",
        )
        return False

    except Exception as e:
        console.print(f"[ERROR] CA health check failed: {e}", style="#B83B5E")
        return False


def find_windows_cert_by_sha256(sha256_fingerprint: str) -> tuple[str, str] | None:
    """Search Windows user ROOT store for a certificate by SHA-256 fingerprint.

    Returns:
        Tuple of (thumbprint, subject) if found, else None.
    """
    ps_cmd = r"""
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root","CurrentUser"
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    foreach ($cert in $store.Certificates) {
        $bytes = $cert.RawData
        $sha256 = [System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)) -replace "-",""
        "$sha256;$($cert.Thumbprint);$($cert.Subject)"
    }
    $store.Close()
    """

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True
    )

    if result.returncode != 0:
        console.print(
            f"[ERROR] Failed to query certificates: {result.stderr.strip()}",
            style="#B83B5E",
        )
        return None

    for line in result.stdout.strip().splitlines():
        try:
            sha256, thumbprint, subject = line.split(";", 2)
            if sha256.strip().lower() == sha256_fingerprint.lower():
                return (thumbprint.strip(), subject.strip())
        except ValueError:
            continue

    return None


def find_linux_cert_by_sha256(sha256_fingerprint: str) -> tuple[str, str] | None:
    """Search Linux trust store for a certificate by SHA-256 fingerprint.

    Returns:
        Tuple of (path, subject) if found, else None.
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
                        cert = x509.load_pem_x509_certificate(
                            cert_data, default_backend()
                        )
                        fp = cert.fingerprint(hashes.SHA256()).hex()
                        if fp.lower() == fingerprint:
                            return (path, cert.subject.rfc4514_string())
                except Exception:
                    continue

    return None
