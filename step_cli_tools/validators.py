import ipaddress
import re
from questionary import Validator, ValidationError

__all__ = ["HostnamePortValidator", "SHA256Validator"]


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

        # Check if it is a valid SHA-256 fingerprint
        if not re.fullmatch(r"[A-Fa-f0-9]{64}", normalized):
            raise ValidationError(
                message="Invalid SHA-256 fingerprint. Must be 64 hexadecimal characters (optionally colon-separated).",
                cursor_position=len(document.text),
            )
