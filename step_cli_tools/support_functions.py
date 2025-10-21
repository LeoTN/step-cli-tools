# --- Standard library imports ---
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import time
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
    "find_windows_cert_by_sha256",
    "find_linux_cert_by_sha256",
]


def ask_boolean_question(prompt_text: str) -> bool:
    """Ask a yes/no question and return a boolean."""
    while True:
        response = input(f"{prompt_text} (y/n): ").strip().lower()
        if response == "y":
            return True
        elif response == "n":
            return False
        else:
            console.print(
                "[ERROR] Invalid input. Please enter 'y' or 'n'.", style="red"
            )


def check_for_update(
    current_version: str, include_prerelease: bool = False
) -> str | None:
    """Check PyPI for updates (cached for 24h by default). Optionally include pre-releases. Return latest version string or None."""
    pkg = "step-cli-tools"
    cache = Path.home() / f".{pkg}" / ".cache" / "update_check.json"
    # Make sure the directory exists
    cache.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()

    # Use cache if less than 24h (by default) old
    if cache.exists():
        try:
            data = json.loads(cache.read_text())
            latest_version = data.get("latest_version")
            chace_lifetime = int(
                config.get("update_config.check_for_updates_cache_lifetime_seconds")
            )
            # Return cached version if still valid
            if (
                latest_version
                and now - data.get("time", 0) < chace_lifetime
                and version.parse(latest_version) > version.parse(current_version)
            ):
                return latest_version
        except json.JSONDecodeError:
            pass

    try:
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/{pkg}/json", timeout=5
        ) as r:
            data = json.load(r)
            # Skip empty or invalid releases
            releases = [r for r, files in data["releases"].items() if files]

        if not include_prerelease:
            releases = [r for r in releases if not version.parse(r).is_prerelease]

        if not releases:
            return

        latest_version = max(releases, key=version.parse)
        cache.write_text(json.dumps({"time": now, "latest_version": latest_version}))

        if version.parse(latest_version) > version.parse(current_version):
            return latest_version

    except Exception:
        return


def install_step_cli(step_bin: str):
    """Download and install step-cli to the given path."""
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
        console.print(f"[ERROR] Unsupported platform: {system}", style="red")
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
        console.print(f"[ERROR] Failed to run step CLI: {e}", style="red")


def execute_step_command(args, step_bin: str, interactive: bool = False):
    """Execute a step CLI command at the given binary path."""
    if not step_bin or not os.path.exists(step_bin):
        console.print(
            "[ERROR] step CLI not found. Please install it first.", style="red"
        )
        return None

    try:
        if interactive:
            result = subprocess.run([step_bin] + args)
            if result.returncode != 0:
                console.print(
                    f"[ERROR] step command failed with exit code {result.returncode}",
                    style="red",
                )
                return None
            return ""
        else:
            result = subprocess.run([step_bin] + args, capture_output=True, text=True)
            if result.returncode != 0:
                console.print(
                    f"[ERROR] step command failed: {result.stderr.strip()}", style="red"
                )
                return None
            return result.stdout.strip()
    except Exception as e:
        console.print(f"[ERROR] Failed to execute step command: {e}", style="red")
        return None


def find_windows_cert_by_sha256(sha256_fingerprint: str) -> tuple[str, str] | None:
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
            style="red",
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
    cert_dir = "/etc/ssl/certs"
    fingerprint = sha256_fingerprint.lower().replace(":", "")

    if not os.path.isdir(cert_dir):
        console.print(f"[ERROR] Cert directory not found: {cert_dir}", style="red")
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
