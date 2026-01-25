# --- Standard library imports ---
import json
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

    cache = SCRIPT_CACHE_DIR / f"{pkg_name}_update_check_cache.json"
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


def install_step_cli(step_bin: Path):
    """
    Download and install the step-cli binary for the current platform.

    Args:
        step_bin: Path to the step binary.
    """

    system = platform.system()
    arch = platform.machine()
    logger.debug(f"Detected platform: {system} {arch}")
    logger.debug(f"Target installation path: {step_bin}")

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

    tmp_dir = Path(tempfile.mkdtemp())
    tmp_path = tmp_dir / Path(url).name
    logger.debug(f"Downloading step-cli from '{url}'...")

    with urlopen(url) as response, tmp_path.open("wb") as out_file:
        out_file.write(response.read())

    logger.debug(f"Archive downloaded to temporary path: {tmp_path}")

    logger.debug(f"Extracting '{archive_type}' archive...")
    if archive_type == "zip":
        with ZipFile(tmp_path, "r") as zip_ref:
            zip_ref.extractall(tmp_dir)
    else:
        with tarfile.open(tmp_path, "r:gz") as tar_ref:
            tar_ref.extractall(tmp_dir)

    # Search recursively for the binary
    matches = [p for p in tmp_dir.rglob(step_bin.name)]

    if not matches:
        logger.error(f"Could not find '{step_bin.name}' in the extracted archive.")
        return

    extracted_path = matches[0]
    logger.debug(f"Using extracted binary: {extracted_path}")

    # Prepare installation path
    step_bin.parent.mkdir(parents=True, exist_ok=True)

    # Delete old binary if exists
    if step_bin.exists():
        logger.debug("Removing existing step binary")
        step_bin.unlink()

    shutil.move(str(extracted_path), str(step_bin))
    step_bin.chmod(0o755)

    logger.debug(f"step-cli binary: {step_bin}")

    try:
        result = subprocess.run(
            [str(step_bin), "version"], capture_output=True, text=True
        )
        logger.info(result.stdout.strip())
    except Exception as e:
        logger.error(f"Failed to run step-cli: {e}")


def execute_step_command(
    args: list[str], step_bin: Path, interactive: bool = False
) -> tuple[bool, str | None]:
    """
    Execute a step-cli command and return output or log errors.

    Args:
        args: List of command-line arguments for step-cli.
        step_bin: Path to the step-cli binary.
        interactive: Whether to run the command interactively.

    Returns:
        Tuple of (success, output)
            - success: True if the command executed successfully
            - output: Captured stdout if non-interactive, otherwise None
    """

    logger.debug(locals())

    if not step_bin.exists():
        logger.error("step-cli not found. Please install it first.")
        return False, None

    try:
        result = subprocess.run(
            [step_bin] + args,
            capture_output=not interactive,
            text=True,
        )

        logger.debug(f"step-cli command exit code: {result.returncode}")
        if not interactive:
            if result.stdout:
                logger.debug(f"step-cli command stdout: {result.stdout.strip()}")
            if result.stderr:
                logger.debug(f"step-cli command stderr: {result.stderr.strip()}")

        if result.returncode != 0:
            error_msg = (
                f"step-cli command exit code: {result.returncode}"
                if interactive
                else f"step-cli command failed: {result.stderr.strip()}"
            )
            logger.error(error_msg)
            return False, (
                result.stdout.strip() if not interactive and result.stdout else None
            )

        return True, None if interactive else result.stdout.strip()

    except Exception as e:
        logger.error(f"Failed to execute step-cli command: {e}")
        return False, None
