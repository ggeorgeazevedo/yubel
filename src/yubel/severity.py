"""Normalized severity model shared across every engine.

Every engine speaks its own dialect (ZAP risk 0-3, Nuclei info/low/.../critical,
CVSS scores, Nikto OSVDB ids). We map all of them onto one ordered scale so
findings can be sorted, thresholded (for CI gating) and de-duplicated.
"""
from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_any(cls, value) -> "Severity":
        """Coerce an engine-native severity into the normalized scale."""
        if isinstance(value, Severity):
            return value
        if value is None:
            return cls.INFO
        if isinstance(value, (int, float)):
            return cls._from_number(float(value))
        text = str(value).strip().lower()
        return _TEXT_MAP.get(text, cls._from_number_maybe(text))

    @classmethod
    def _from_number(cls, n: float) -> "Severity":
        # Treat 0-10 as CVSS-like; 0-4 as our own scale.
        if n <= 4 and n == int(n):
            try:
                return cls(int(n))
            except ValueError:
                pass
        if n >= 9.0:
            return cls.CRITICAL
        if n >= 7.0:
            return cls.HIGH
        if n >= 4.0:
            return cls.MEDIUM
        if n > 0.0:
            return cls.LOW
        return cls.INFO

    @classmethod
    def _from_number_maybe(cls, text: str) -> "Severity":
        try:
            return cls._from_number(float(text))
        except ValueError:
            return cls.INFO


_TEXT_MAP = {
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "information": Severity.INFO,
    "note": Severity.INFO,
    "unknown": Severity.INFO,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "warning": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "important": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "severe": Severity.CRITICAL,
    "blocker": Severity.CRITICAL,
    # ZAP risk codes
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}
