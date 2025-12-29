import ipaddress
import re
from questionary import Validator, ValidationError

__all__ = [
    "HostnamePortValidator",
    "SHA256Validator",
    "SHA256OrNameValidator",
    "int_range_validator",
    "str_allowed_validator",
    "bool_validator",
    "server_validator",
]


class HostnamePortValidator(Validator):
    def validate(self, document):
        value = document.text.strip()

        # Check if port is specified
        if ":" in value:
            host_part, port_part = value.rsplit(":", 1)
            if not port_part.isdigit() or not (1 <= int(port_part) <= 65535):
                raise ValidationError(
                    message=f"Invalid port: {port_part}. Must be between 1 and 65535.",
                    cursor_position=len(document.text),
                )
        else:
            host_part = value

        # Check if host is a valid IP address
        try:
            ipaddress.ip_address(host_part)
            return
        except ValueError:
            pass

        # Check hostname validity
        hostname_regex = re.compile(
            r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
        )
        if not hostname_regex.match(host_part):
            raise ValidationError(
                message=f"Invalid hostname: {host_part}. Must not contain spaces or invalid characters.",
                cursor_position=len(document.text),
            )


class SHA256Validator(Validator):
    def validate(self, document):
        value = document.text.strip()

        # Delete colons if present
        normalized = value.replace(":", "")

        # Check if it is a valid SHA256 fingerprint
        if not re.fullmatch(r"[A-Fa-f0-9]{64}", normalized):
            raise ValidationError(
                message="Invalid SHA256 fingerprint. Must be 64 hexadecimal characters (optionally colon-separated).",
                cursor_position=len(document.text),
            )


class SHA256OrNameValidator(Validator):
    def validate(self, document):
        value = document.text.strip()

        # Delete colons if present
        normalized = value.replace(":", "")

        # Automatically accepts SHA256 fingerprints
        if not re.fullmatch(r"[A-Za-z0-9\s\-\_\*]+", normalized):
            raise ValidationError(
                message="Invalid input. Enter a SHA256 fingerprint or a name with optional '*'",
                cursor_position=len(document.text),
            )


# --- Validators used by the configuration class ---


def int_range_validator(min_value: int, max_value: int):
    """
    Returns a validator function that ensures an integer is within [min_value, max_value].

    Args:
        min_value: Minimum allowed integer value (inclusive).
        max_value: Maximum allowed integer value (inclusive).

    Returns:
        A function(value) -> Optional[str]:
            - Returns None if valid.
            - Returns a string describing the problem if invalid.
    """

    def validator(value):
        if not isinstance(value, int):
            return f"Invalid type: expected int, got {type(value).__name__}"
        if value < min_value or value > max_value:
            return f"Value {value} out of range ({min_value}–{max_value})"
        return None

    return validator


def str_allowed_validator(allowed: list[str]):
    """
    Returns a validator function that ensures a string value is one of the allowed values.

    Args:
        allowed: List of allowed string values.

    Returns:
        A function(value) -> Optional[str]:
            - Returns None if valid.
            - Returns a descriptive string if invalid.
    """

    def validator(value):
        if not isinstance(value, str):
            return f"Invalid type: expected str, got {type(value).__name__}"
        if value not in allowed:
            allowed_str = ", ".join(map(repr, allowed))
            return f"Invalid value '{value}'. Allowed values: {allowed_str}"
        return None

    return validator


def bool_validator(value) -> str | None:
    """
    Validates that a value is of type bool.

    Args:
        value: The value to validate.

    Returns:
        None if valid, otherwise a descriptive string.
    """

    if not isinstance(value, bool):
        return f"Invalid type: expected bool, got {type(value).__name__}"
    return None


def server_validator(value: str) -> str | None:
    """
    Validate a server string with optional port.

    Args:
        value: A string like "hostname" or "hostname:port" or "127.0.0.1:8080".

    Returns:
        None if valid, otherwise a descriptive string.
    """

    if not isinstance(value, str):
        return f"Invalid type: expected string, got {type(value).__name__}"

    value = value.strip()
    if not value:
        # An empty string is allowed in the config file
        return None

    # Split host and optional port
    if ":" in value:
        host_part, port_part = value.rsplit(":", 1)
        if not port_part.isdigit() or not (1 <= int(port_part) <= 65535):
            return f"Invalid port: {port_part}. Must be between 1 and 65535."
    else:
        host_part = value

    # Check if host is a valid IP address
    try:
        ipaddress.ip_address(host_part)
        return None  # valid IP
    except ValueError:
        pass

    # Validate hostname format
    hostname_regex = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
    )
    if not hostname_regex.match(host_part):
        return (
            f"Invalid hostname: '{host_part}'. "
            "Must not contain spaces or invalid characters."
        )

    return None  # valid
