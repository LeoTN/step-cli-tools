# --- Standard library imports ---
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

# --- Local application imports ---
from ..common import SCRIPT_CERT_DIR, logger
from ..utils.paths import sanitize_filename

# --- Root CA Info ---


@dataclass(frozen=True)
class RootCAInfo:
    ca_name: str
    fingerprint_sha256: str


# --- Certificate Request Info ---


@dataclass
class CRI_OutputFormat_Information:
    """Information about supported certificate output formats which is used for questionary prompts."""

    menu_item_name: str
    menu_item_description: str


class CRI_OutputFormat(Enum):
    """Supported certificate output formats."""

    PEM_CRT_KEY = CRI_OutputFormat_Information(
        "PEM CRT & KEY (default)", "Two separate PEM-encoded crt and key files."
    )
    PEM_BUNDLE = CRI_OutputFormat_Information(
        "PEM BUNDLE", "One PEM-encoded crt bundle file containing the crt and key."
    )
    PFX_BUNDLE = CRI_OutputFormat_Information(
        "PFX BUNDLE", "One PFX-encoded bundle file containing the crt and key."
    )


@dataclass
class CRI_KeyAlgorithm_Information:
    """Information about supported certificate key algorithms which is used for questionary prompts."""

    # The argument used for the actual step-cli command (should not be changed)
    arg: str
    menu_item_name: str
    menu_item_description: str


class CRI_KeyAlgorithm(Enum):
    """Supported certificate key algorithms."""

    EC = CRI_KeyAlgorithm_Information(
        "EC",
        "EC (default)",
        "Elliptic Curve; efficient and secure for most modern applications.",
    )
    RSA = CRI_KeyAlgorithm_Information(
        "RSA", "RSA", "Traditional RSA algorithm; widely supported."
    )
    OKP = CRI_KeyAlgorithm_Information(
        "OKP",
        "OKP",
        "Octet Key Pair; uses modern elliptic curves for high-performance cryptography.",
    )


@dataclass
class CRI_ECCurve_Information:
    """Information about supported elliptic curves which is used for questionary prompts."""

    # The argument used for the actual step-cli command (should not be changed)
    arg: str
    menu_item_name: str
    menu_item_description: str


class CRI_ECCurve(Enum):
    """Supported elliptic curves for EC keys."""

    P256 = CRI_ECCurve_Information(
        "P-256",
        "P-256 (default)",
        "Also known as secp256r1; widely supported and secure for most use cases.",
    )
    P384 = CRI_ECCurve_Information(
        "P-384",
        "P-384",
        "Provides higher security than P-256 with a longer key length.",
    )
    P521 = CRI_ECCurve_Information(
        "P-521", "P-521", "Very strong security, but slower and less widely supported."
    )


@dataclass
class CRI_RSAKeySize_Information:
    """Information about supported RSA key sizes which is used for questionary prompts."""

    # The argument used for the actual step-cli command (should not be changed)
    arg: str
    menu_item_name: str
    menu_item_description: str


class CRI_RSAKeySize(Enum):
    """Supported key sizes for RSA keys."""

    RSA2048 = CRI_RSAKeySize_Information(
        "2048", "2048 (default)", "Standard key size; secure for most applications."
    )
    RSA3072 = CRI_RSAKeySize_Information(
        "3072",
        "3072",
        "Stronger security than 2048-bit, with moderate performance cost.",
    )
    RSA4096 = CRI_RSAKeySize_Information(
        "4096",
        "4096",
        "Very strong security; slower but highly secure for sensitive use cases.",
    )


@dataclass
class CRI_OKPCurve_Information:
    """Information about supported OKP elliptic curves which is used for questionary prompts."""

    # The argument used for the actual step-cli command (should not be changed)
    arg: str
    menu_item_name: str
    menu_item_description: str


class CRI_OKPCurve(Enum):
    """Supported elliptic curves for OKP keys."""

    Ed25519 = CRI_OKPCurve_Information(
        "Ed25519",
        "Ed25519 (default)",
        "High-performance signature algorithm with strong security.",
    )


@dataclass
class CertificateRequestInfo:
    """Data model for a basic certificate request."""

    # Backing field for subject_name (do not access directly)
    _subject_name: str = field(repr=False)

    output_format: CRI_OutputFormat

    # SAN entries (always available after __post_init__)
    san_entries: list[str] = field(default_factory=list)

    # Key options
    key_algorithm: CRI_KeyAlgorithm = CRI_KeyAlgorithm.EC
    ecc_curve: CRI_ECCurve = CRI_ECCurve.P256
    rsa_size: CRI_RSAKeySize = CRI_RSAKeySize.RSA2048
    okp_curve: CRI_OKPCurve = CRI_OKPCurve.Ed25519

    # Optional validity overrides
    valid_since: datetime | None = None
    valid_until: datetime | None = None

    # Derived fields (always set in __post_init__ / setter)
    final_output_dir: Path = field(init=False)
    final_crt_output_name_with_suffix: Path = field(init=False)
    final_key_output_name_with_suffix: Path = field(init=False)
    final_pem_bundle_output_name_with_suffix: Path = field(init=False)
    final_pfx_bundle_output_name_with_suffix: Path = field(init=False)

    def __post_init__(self):
        # Generate timestamp
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")

        # Output folder with timestamp
        self.final_output_dir = Path(SCRIPT_CERT_DIR) / self.timestamp

        # Initialize subject_name via setter to trigger synchronization logic
        initial_subject = self._subject_name
        self.subject_name = initial_subject

        # Ensure timezone awareness
        if self.valid_since and self.valid_since.tzinfo is None:
            self.valid_since = self.valid_since.astimezone()
            logger.warning(
                f"Validity start date is not timezone aware, using local timezone 'UTC {self.valid_since.utcoffset()}'."
            )

        if self.valid_until and self.valid_until.tzinfo is None:
            self.valid_until = self.valid_until.astimezone()
            logger.warning(
                f"Validity end date is not timezone aware, using local timezone 'UTC {self.valid_until.utcoffset()}'."
            )

        # Normalize key options
        if self.key_algorithm == CRI_KeyAlgorithm.RSA:
            self.rsa_size = self.rsa_size or CRI_RSAKeySize.RSA2048
        else:
            self.ecc_curve = self.ecc_curve or CRI_ECCurve.P256

    @property
    def subject_name(self) -> str:
        """Return the current subject name."""

        return self._subject_name

    @subject_name.setter
    def subject_name(self, value: str):
        """
        Update subject_name and keep SAN entries and derived filenames in sync.
        """

        old_value = getattr(self, "_subject_name", None)
        self._subject_name = value

        # Update SAN entries
        if old_value is not None:
            # Replace old subject name occurrences
            self.san_entries = [
                value if entry == old_value else entry for entry in self.san_entries
            ]

        # Ensure subject_name is always present in SAN entries
        if value not in self.san_entries:
            self.san_entries.append(value)

        # Update derived filenames
        self._update_derived_filenames(value)

    def _update_derived_filenames(self, subject_name: str):
        """Update all filename fields derived from subject_name."""

        self.final_crt_output_name_with_suffix = Path(
            sanitize_filename(f"{subject_name}.crt")
        )
        self.final_key_output_name_with_suffix = Path(
            sanitize_filename(f"{subject_name}.key")
        )
        self.final_pem_bundle_output_name_with_suffix = Path(
            sanitize_filename(f"{subject_name}.pem")
        )
        self.final_pfx_bundle_output_name_with_suffix = Path(
            sanitize_filename(f"{subject_name}.pfx")
        )

    def validate(self):
        if not self.subject_name:
            raise ValueError("Subject name must not be empty")

        if (
            self.valid_since
            and self.valid_until
            and self.valid_since > self.valid_until
        ):
            raise ValueError("Validity start date must be before end date")

    # Used to determine the correct user prompt and step-cli argument to pass
    def is_key_algorithm_ec(self) -> bool:
        return self.key_algorithm == CRI_KeyAlgorithm.EC

    def is_key_algorithm_rsa(self) -> bool:
        return self.key_algorithm == CRI_KeyAlgorithm.RSA

    def is_key_algorithm_okp(self) -> bool:
        return self.key_algorithm == CRI_KeyAlgorithm.OKP

    def is_output_format_pem(self) -> bool:
        return self.output_format in {
            CRI_OutputFormat.PEM_CRT_KEY,
            CRI_OutputFormat.PEM_BUNDLE,
        }

    def is_output_format_pfx(self) -> bool:
        return self.output_format == CRI_OutputFormat.PFX_BUNDLE


# --- Functions ---


# Used by convert_certificate()
@dataclass
class CertificateConversionResult:
    format: CRI_OutputFormat
    certificate: Path | None = None
    private_key: Path | None = None
    pem_bundle: Path | None = None
    pfx: Path | None = None
