# --- Standard library imports ---
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen
from zipfile import ZipFile

# --- Third-party imports ---
from packaging import version

# --- Local application imports ---
from ..common import SCRIPT_CACHE_DIR, logger
from ..configuration import config


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

    cache = Path(SCRIPT_CACHE_DIR)
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
            return

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
        return


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
        return

    try:
        if interactive:
            logger.info("--- Interactive step-cli mode start ---")
            result = subprocess.run([step_bin] + args)
            logger.info("--- Interactive step-cli mode end ---")
            logger.debug(f"step-cli command exit code: {result.returncode}")

            if result.returncode != 0:
                logger.error(f"step-cli command exit code: {result.returncode}")
                return

            return "Interactive command executed successfully."
        else:
            result = subprocess.run([step_bin] + args, capture_output=True, text=True)
            logger.debug(f"step-cli command exit code: {result.returncode}")

            if result.returncode != 0:
                logger.error(f"step-cli command failed: {result.stderr.strip()}")
                return

            return result.stdout.strip()

    except Exception as e:
        logger.error(f"Failed to execute step-cli command: {e}")
        return
