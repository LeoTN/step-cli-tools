# --- Standard library imports ---
import ipaddress
import re
from datetime import datetime, timezone

# --- Third-party imports ---
from questionary import ValidationError, Validator

# --- Local application imports ---
from ..common import logger


class CertificateSubjectNameValidator(Validator):
    """
    Validates a certificate Subject Name or SAN entry.
    Supports:
      - CN/DN (escaped)
      - DNS hostnames with optional wildcard in first label
      - IPv4 and IPv6 addresses
    """

    def __init__(self, accept_blank: bool = False):
        self.accept_blank = accept_blank
        super().__init__()

    # Characters that must be escaped in DN (RFC 4514)
    DN_ESCAPE_CHARS = r",+\"\\<>;="

    # DNS regex allowing optional wildcard in first label
    DNS_WILDCARD_REGEX = re.compile(
        r"^(?:\*\.)?(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
    )

    def validate(self, document):
        value = document.text.strip()

        # Accept blank input if configured
        if self.accept_blank and not value:
            return

        # Check if value is a valid IP address
        try:
            ipaddress.ip_address(value)
            return
        except ValueError:
            pass

        # Reject IPv4-like values that are not valid IPv4
        if re.match(r"^\d+(\.\d+){3}$", value):
            raise ValidationError(
                message=f"Invalid IPv4 address: {value}",
                cursor_position=len(document.text),
            )

        # Reject IPv6-like values that are not valid IPv6
        if ":" in value:
            raise ValidationError(
                message=f"Invalid IPv6 address: {value}",
                cursor_position=len(document.text),
            )

        # Check if value looks like a DN (contains '=')
        if "=" in value:
            # Reject unescaped illegal characters
            unescaped_illegal = re.compile(
                r"(?<!\\)[" + re.escape(self.DN_ESCAPE_CHARS) + r"]"
            )
            if unescaped_illegal.search(value):
                raise ValidationError(
                    message=f"Invalid DN: contains illegal unescaped characters",
                    cursor_position=len(document.text),
                )
            return  # Passed DN check

        # Otherwise validate as DNS hostname with optional wildcard
        if not self.DNS_WILDCARD_REGEX.match(value):
            raise ValidationError(
                message=f"Invalid hostname or wildcard: {value}",
                cursor_position=len(document.text),
            )


class HostnameOrIPAddressAndOptionalPortValidator(Validator):
    def validate(self, document):
        value = document.text.strip()

        host_part = value
        port_part = None

        # Check if port is specified
        if ":" in value and not value.startswith("["):
            # Simple IPv4 or hostname with optional port
            host_part, port_part = value.rsplit(":", 1)
        elif value.startswith("[") and "]" in value:
            # IPv6 literal with optional port: [IPv6]:port
            host_end = value.index("]")
            host_part = value[1:host_end]
            if host_end + 1 < len(value) and value[host_end + 1] == ":":
                port_part = value[host_end + 2 :]

        # Validate port if present
        if port_part:
            if not port_part.isdigit() or not (1 <= int(port_part) <= 65535):
                raise ValidationError(
                    message=f"Invalid port: {port_part}. Must be between 1 and 65535",
                    cursor_position=len(document.text),
                )

        # Check if host is a valid IP address
        try:
            ipaddress.ip_address(host_part)
            return
        except ValueError:
            pass

        # Reject IPv4-like values that are not valid IPv4 addresses
        ipv4_like_regex = re.compile(r"^\d+(\.\d+){3}$")
        if ipv4_like_regex.match(host_part):
            raise ValidationError(
                message=f"Invalid IPv4 address: {host_part}",
                cursor_position=len(document.text),
            )

        # Reject IPv6-like values that are not valid IPv6 addresses
        if ":" in host_part:
            raise ValidationError(
                message=f"Invalid IPv6 address: {host_part}",
                cursor_position=len(document.text),
            )

        # Check hostname validity
        hostname_regex = re.compile(
            r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
            r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
        )
        if not hostname_regex.match(host_part):
            raise ValidationError(
                message=f"Invalid hostname or IP address: {host_part}",
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

        # Accept SHA256 fingerprints
        if not re.fullmatch(r"[A-Za-z0-9\s\-\_\*]+", normalized):
            raise ValidationError(
                message="Invalid input. Enter a SHA256 fingerprint or a name with optional '*'",
                cursor_position=len(document.text),
            )


class DateTimeValidator(Validator):
    """
    Validates a datetime value including time.
    Supports:
      - multiple common datetime string formats
      - optional lower and upper datetime bounds
    """

    SUPPORTED_FORMATS = (
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d.%m.%Y",
        "%d.%m.%Y %H:%M",
        "%d.%m.%Y %H:%M:%S",
        "%d/%m/%Y",
        "%d/%m/%Y %H:%M",
        "%d/%m/%Y %H:%M:%S",
    )

    def __init__(
        self,
        *,
        recommended_format: str = "%Y-%m-%d %H:%M:%S",
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        accept_blank: bool = False,
    ):
        self.recommended_format = recommended_format
        self.not_before = self._ensure_timezone(not_before)
        self.not_after = self._ensure_timezone(not_after)
        self.accept_blank = accept_blank
        super().__init__()

    @staticmethod
    def _ensure_timezone(value: datetime | None) -> datetime | None:
        if value is None:
            return None

        if value.tzinfo is None:
            logger.warning("Datetime is not timezone aware, assuming UTC.")
            return value.replace(tzinfo=timezone.utc)

        return value

    def _parse_datetime(self, value: str) -> datetime | None:
        # First try ISO-8601 (fast path)
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass

        # Fallback to supported legacy formats
        for fmt in self.SUPPORTED_FORMATS:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue

        return None

    def validate(self, document):
        value = document.text.strip()
        now_recommended = datetime.now(timezone.utc).strftime(self.recommended_format)

        # Accept blank input if configured
        if self.accept_blank and not value:
            return

        parsed_datetime = self._parse_datetime(value)
        if parsed_datetime is None:
            raise ValidationError(
                message=(
                    f"Invalid date/time value. "
                    f"Recommended format: {now_recommended}"
                ),
                cursor_position=len(document.text),
            )

        # Normalize parsed datetime
        if parsed_datetime.tzinfo is None:
            parsed_datetime = parsed_datetime.replace(tzinfo=timezone.utc)

        # Validate lower bound
        if self.not_before is not None and parsed_datetime < self.not_before:
            raise ValidationError(
                message=(
                    f"'{value}' is earlier than allowed minimum "
                    f"'{self.not_before.strftime(self.recommended_format)}'"
                ),
                cursor_position=len(document.text),
            )

        # Validate upper bound
        if self.not_after is not None and parsed_datetime > self.not_after:
            raise ValidationError(
                message=(
                    f"'{value}' is later than allowed maximum "
                    f"'{self.not_after.strftime(self.recommended_format)}'"
                ),
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
        return

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
        return

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
    return


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
        return

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
        return
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

    return
