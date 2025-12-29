from dataclasses import dataclass


__all__ = ["CARootInfo"]


@dataclass(frozen=True)
class CARootInfo:
    ca_name: str
    fingerprint_sha256: str
