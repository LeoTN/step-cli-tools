# --- Standard library imports ---
import re
from datetime import datetime
from pathlib import Path

# --- Local application imports ---
from .common import logger

WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

UMLAUT_MAP = {
    "Ä": "Ae",
    "Ö": "Oe",
    "Ü": "Ue",
    "ä": "ae",
    "ö": "oe",
    "ü": "ue",
    "ß": "ss",
}


def sanitize_filename(value: str) -> str:
    """
    Convert a string into a filesystem-safe filename.

    Args:
        value: The string to sanitize

    Returns:
        The sanitized filename
    """

    original_value = value
    path = Path(value)

    stem = path.stem
    suffix = path.suffix

    # Replace German umlauts
    for umlaut, replacement in UMLAUT_MAP.items():
        stem = stem.replace(umlaut, replacement)

    # Replace asterisk with a readable token
    stem = stem.replace("*", "wildcard")

    # Replace path separators and whitespace
    stem = re.sub(r"[\\/]+", "_", stem)
    stem = re.sub(r"\s+", "_", stem)

    # Allow only safe characters
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", stem)

    # Collapse multiple underscores
    stem = re.sub(r"_+", "_", stem)

    # Collapse multiple dots
    stem = re.sub(r"\.{2,}", ".", stem)

    # Delete leading/trailing dots and underscores
    stem = stem.strip("._")

    if not stem:
        stem = f"sanitized_filename_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S-%f')}"
        logger.warning(
            f"Filename '{original_value}' is empty after sanitization. Using '{stem}' instead."
        )

    if stem.upper() in WINDOWS_RESERVED_NAMES:
        logger.warning(
            f"Filename '{stem}' is a reserved name on Windows. Appending underscore."
        )
        stem = f"{stem}_"

    filename = f"{stem}{suffix}"

    if len(filename) > 255:
        logger.warning(
            f"Filename '{filename[:255]}...' is too long. Truncating to 255 characters."
        )
        filename = filename[:255]

    logger.debug(f"Sanitized filename: {filename}")
    return filename


def join_safe_path(
    target_dir: Path, target_file_name_with_suffix: Path, ensure_target_dir_exists=True
) -> Path:
    """
    Join a target directory with a sanitized filename and return the final path for the file.
    Ensures no filename collisions by appending a timestamp before the extension if necessary.

    Args:
        target_dir: The base directory for the file.
        target_file_name_with_suffix: The desired filename with suffix which will be sanitized.
        ensure_target_dir_exists: If True, the target directory will be created if it doesn't exist.

    Returns:
        The final path for the file.
    """

    # Sanitize the filename
    sanitized_filename = sanitize_filename(target_file_name_with_suffix.name)
    stem = Path(sanitized_filename).stem
    suffix = "".join(Path(sanitized_filename).suffixes)

    # Ensure target directory exists if necessary
    if ensure_target_dir_exists:
        logger.debug(f"Creating target directory: {target_dir}")
        target_dir.mkdir(parents=True, exist_ok=True)

    final_path = target_dir / sanitized_filename

    # If file already exists, append timestamp before the suffix
    if final_path.exists():
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")
        final_path = target_dir / f"{stem}_{timestamp}{suffix}"

    logger.debug(f"Final path: {final_path}")
    return final_path
