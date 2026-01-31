# --- Standard library imports ---
import socket
import ssl
from urllib.parse import urlparse

# --- Third-party imports ---
import requests

# --- Local application imports ---
from ..common import get_masked_url_for_logging, logger


def is_server_certificate_trusted(
    server_url: str, use_system_store: bool = True, timeout_seconds: int = 5
) -> bool:
    """
    Check if the server TLS certificate is trusted by the system.

    Args:
        server_url: The URL of the server to check.
        use_system_store: If True, use the system trust store. If False, use the default certifi bundle.
        timeout_seconds: Timeout in seconds.

    Returns:
        True if the server certificate is trusted, False otherwise.
    """

    masked_server_url = get_masked_url_for_logging(server_url)
    logger.debug(
        f"server_url={masked_server_url}, use_system_store={use_system_store}, timeout_seconds={timeout_seconds}"
    )

    if use_system_store:
        return _is_certificate_trusted_via_system_store(server_url, timeout_seconds)

    try:
        requests.get(server_url, timeout=timeout_seconds)
        logger.debug(f"Server certificate from '{masked_server_url}' is trusted")
        return True
    except requests.exceptions.SSLError as e:
        logger.debug(
            f"Server certificate from '{masked_server_url}' is not trusted: {e}"
        )
        return False
    except requests.exceptions.RequestException as e:
        logger.error(
            f"Failed to check server certificate from '{masked_server_url}': {e}"
        )
        return False


def _is_certificate_trusted_via_system_store(
    server_url: str,
    timeout_seconds: int,
) -> bool:
    """
    Perform a TLS handshake using the OS trust store.

    Args:
        server_url: The URL of the server to check.
        timeout_seconds: Timeout in seconds.

    Returns:
        True if the server certificate is trusted (system trust store), False otherwise.
    """

    masked_server_url = get_masked_url_for_logging(server_url)

    parsed_url = urlparse(server_url)
    hostname = parsed_url.hostname
    port = parsed_url.port or 443

    if hostname is None:
        logger.error(
            f"Invalid server URL provided: '{masked_server_url}'.",
        )
        return False

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port), timeout=timeout_seconds
        ) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                logger.debug(
                    f"Server certificate from '{masked_server_url}' is trusted (system trust store)",
                )
                return True
    except ssl.SSLError as e:
        logger.debug(
            f"Server certificate from '{masked_server_url}' is not trusted (system trust store): {e}",
        )
        return False
    except OSError as e:
        logger.error(
            f"Failed to check server certificate from '{masked_server_url}': {e}",
        )
        return False


def is_host_available(server_url: str, timeout_seconds: int = 5) -> bool:
    """
    Check if a host is reachable on the given port via TCP.

    Args:
        server_url: The server URL containing hostname and optional port.
        timeout_seconds: Timeout in seconds.

    Returns:
        True if the host is reachable on the specified port, False otherwise.
    """

    masked_server_url = get_masked_url_for_logging(server_url)

    parsed_url = urlparse(server_url)
    hostname = parsed_url.hostname
    # Use default port if not specified
    if parsed_url.port:
        port = parsed_url.port
    elif parsed_url.scheme == "http":
        port = 80
    else:
        port = 443

    if hostname is None:
        logger.error(f"Invalid server URL provided: '{masked_server_url}'")
        return False

    logger.debug(f"host='{hostname}', port={port}, timeout_seconds={timeout_seconds}")

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=timeout_seconds,
        ):
            logger.debug(f"Host '{hostname}' is reachable on port {port}")
            return True
    except (OSError, socket.timeout) as e:
        logger.debug(f"Host '{hostname}' is not reachable on port {port}: {e}")
        return False
