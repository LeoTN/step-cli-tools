# --- Standard library imports --- #
import re
import ssl
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

# --- Third-party imports --- #
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

# --- Local application imports --- #
from .common import DEFAULT_QY_STYLE, SCRIPT_CACHE_DIR, STEP_BIN, console, logger, qy
from .data_classes import CertificateRequestInfo, RootCAInfo
from .support_functions_general import execute_step_command


def execute_ca_request(
    url: str,
    trust_unknown_default: bool = False,
    timeout: int = 10,
) -> str | None:
    """
    Perform an HTTPS request to the CA, handling untrusted certificates if needed.

    Args:
        url: URL to request.
        trust_unknown_default: If True, trust unverified SSL certificates.
        timeout: Timeout in seconds.

    Returns:
        Response body as string, or None on failure or user abort.
    """

    logger.debug(locals())

    def do_request(context):
        with urlopen(url, context=context, timeout=timeout) as response:
            logger.debug(f"Received HTTP response status code: {response.status}")
            return response.read().decode("utf-8").strip()

    context = (
        ssl._create_unverified_context()
        if trust_unknown_default
        else ssl.create_default_context()
    )

    try:
        return do_request(context)

    except URLError as e:
        reason = getattr(e, "reason", None)

        logger.debug(f"URLError: {e}")

        if isinstance(reason, ssl.SSLCertVerificationError):
            logger.warning("Server provided an unknown or self-signed certificate.")

            console.print()
            answer = qy.confirm(
                message=f"Do you want to trust '{url}' this time?",
                default=False,
                style=DEFAULT_QY_STYLE,
            ).ask()

            if not answer:
                logger.info("Operation cancelled by user.")
                return

            logger.debug("Retrying request with unverified SSL context")

            try:
                return do_request(ssl._create_unverified_context())
            except Exception as retry_error:
                logger.error(
                    f"Retry failed: {retry_error}\n\nIs the port correct and the server available?"
                )
                return

        logger.error(
            f"Connection failed: {e}\n\nIs the port correct and the server available?"
        )
        return

    except Exception as e:
        logger.error(
            f"Request failed: {e}\n\nIs the port correct and the server available?"
        )
        return


def execute_certificate_request(
    request_parameters: CertificateRequestInfo,
    ca_base_url: str,
) -> tuple[Path, Path] | None:
    """
    Request a new certificate from a step-ca server.

    Args:
        request_parameters: Certificate request parameters.
        ca_base_url: Base URL of the CA server, including protocol and port.

    Returns:
        Tuple of certificate and key paths on success, None on error or user cancel.
    """

    logger.debug(locals())

    try:
        request_parameters.validate()
    except ValueError as e:
        logger.error(f"Invalid certificate request parameters: {e}")
        return

    # The step-ca server can only return the certificate and key in this format
    tmp_crt_file_path = Path(SCRIPT_CACHE_DIR) / f"{request_parameters.timestamp}.crt"
    tmp_key_file_path = Path(SCRIPT_CACHE_DIR) / f"{request_parameters.timestamp}.key"

    args = [
        "ca",
        "certificate",
        request_parameters.subject_name,
        tmp_crt_file_path,
        tmp_key_file_path,
        "--ca-url",
        ca_base_url,
        "--force",
    ]

    # Just a safety measure as the entries should contain the subject name at least
    if request_parameters.san_entries:
        for san_entry in request_parameters.san_entries:
            args.extend(["--san", san_entry])

    # The logic is already handled in the data class
    if request_parameters.key_algorithm:
        args.extend(["--kty", request_parameters.key_algorithm.value.arg])

    if request_parameters.is_key_algorithm_ec():
        args.extend(["--curve", request_parameters.ecc_curve.value.arg])

    if request_parameters.is_key_algorithm_okp():
        args.extend(["--curve", request_parameters.okp_curve.value.arg])

    if request_parameters.is_key_algorithm_rsa():
        args.extend(["--size", request_parameters.rsa_size.value.arg])

    if request_parameters.valid_since:
        args.extend(
            [
                "--not-before",
                request_parameters.valid_since.isoformat(timespec="seconds"),
            ]
        )

    if request_parameters.valid_until:
        args.extend(
            [
                "--not-after",
                request_parameters.valid_until.isoformat(timespec="seconds"),
            ]
        )

    # Interactive because the the user will be asked for the JWK password
    result = execute_step_command(args=args, step_bin=STEP_BIN, interactive=True)
    if not result:
        logger.error("Certificate request failed.")
        return

    return tmp_crt_file_path, tmp_key_file_path


def check_ca_health(ca_base_url: str, trust_unknown_default: bool = False) -> bool:
    """
    Check the health endpoint of a CA server via HTTPS.

    Args:
        ca_base_url: Base URL of the CA server, including protocol and port.
        trust_unknown_default: If True, trust unverified SSL certificates.

    Returns:
        True if the CA is healthy, False otherwise.
    """

    logger.debug(locals())

    health_url = ca_base_url.rstrip("/") + "/health"

    response = execute_ca_request(
        url=health_url,
        trust_unknown_default=trust_unknown_default,
    )

    if response is None:
        logger.debug("CA health check failed due to missing response")
        return False

    logger.debug(f"Health endpoint response: {response}")

    if "ok" in response.lower():
        logger.info(f"CA at '{ca_base_url}' is healthy.")
        return True

    logger.error(f"CA health check failed for '{ca_base_url}'.")
    return False


def get_ca_root_info(
    ca_base_url: str,
    trust_unknown_default: bool = False,
) -> RootCAInfo | None:
    """
    Fetch the first root certificate from a Smallstep CA and return its name
    and SHA256 fingerprint.

    Args:
        ca_base_url: Base URL of the CA (e.g. https://my-ca-host:9000).
        trust_unknown_default: Skip SSL verification immediately if True.

    Returns:
        RootCAInfo on success, None on error or user cancel.
    """

    logger.debug(locals())

    roots_url = ca_base_url.rstrip("/") + "/roots.pem"

    pem_bundle = execute_ca_request(
        url=roots_url,
        trust_unknown_default=trust_unknown_default,
    )

    if pem_bundle is None:
        logger.debug("Failed to retrieve roots.pem")
        return

    try:
        # Extract first PEM certificate
        match = re.search(
            "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            pem_bundle,
            re.S,
        )
        if not match:
            logger.error("No certificate found in roots.pem")
            return

        logger.debug("Loading PEM certificate")
        cert = x509.load_pem_x509_certificate(
            match.group(0).encode(),
            default_backend(),
        )

        # Compute SHA256 fingerprint
        fingerprint_hex = cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint = ":".join(
            fingerprint_hex[i : i + 2] for i in range(0, len(fingerprint_hex), 2)
        )

        # Extract CA name (CN preferred, always string)
        logger.debug(f"Computed SHA256 fingerprint: {fingerprint}")

        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            ca_name = (
                str(cn[0].value)
                if cn and cn[0].value is not None
                else str(cert.subject.rfc4514_string())
            )
        except Exception as e:
            logger.warning(f"Unable to retrieve CA name: {e}")
            ca_name = "Unknown CA"

        logger.info("Root CA information retrieved successfully.")

        return RootCAInfo(
            ca_name=ca_name,
            fingerprint_sha256=fingerprint.replace(":", ""),
        )

    except Exception as e:
        logger.error(f"Failed to process CA root certificate: {e}")
        return
