import platform
import os
import sys
import subprocess
import shutil
import tempfile
import tarfile
import re

from zipfile import ZipFile
from urllib.request import urlopen
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from rich.console import Console
from rich.panel import Panel


console = Console()


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


def ask_string_question(prompt_text: str) -> str:
    """Ask for a non-empty string and return it."""
    while True:
        response = input(f"{prompt_text}: ").strip()
        if response:
            return response
        else:
            console.print(
                "[ERROR] Input cannot be empty. Please enter a valid string.",
                style="red",
            )


def get_step_binary_path() -> str:
    """Return absolute path to step-cli binary depending on OS."""
    home = os.path.expanduser("~")
    system = platform.system()
    if system == "Windows":
        return os.path.join(home, "bin", "step.exe")
    elif system in ("Linux", "Darwin"):
        return os.path.join(home, "bin", "step")
    else:
        raise OSError(f"Unsupported platform: {system}")


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

    console.print(f"[INFO] step CLI installed to {step_bin}")

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

    for cert_file in os.listdir(cert_dir):
        path = os.path.join(cert_dir, cert_file)
        if os.path.isfile(path):
            try:
                with open(path, "rb") as f:
                    cert_data = f.read()
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                    fp = cert.fingerprint(hashes.SHA256()).hex()
                    if fp.lower() == fingerprint:
                        return (path, cert.subject.rfc4514_string())
            except Exception:
                continue

    return None
