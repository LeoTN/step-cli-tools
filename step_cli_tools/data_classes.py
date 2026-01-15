# --- Standard library imports ---
from dataclasses import dataclass

__all__ = ["RootCAInfo"]


@dataclass(frozen=True)
class RootCAInfo:
    ca_name: str
    fingerprint_sha256: str
