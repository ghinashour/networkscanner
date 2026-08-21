"""
Fingerprinting module for device identification.
"""

"""Fingerprinting package."""

# Use relative import so `src.fingerprinting` works when project root is on sys.path.
from .device_fingerprinter import DeviceFingerprinter

__all__ = ["DeviceFingerprinter"]
