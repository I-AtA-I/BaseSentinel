from __future__ import annotations

import ctypes
import os
from ctypes import wintypes


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _require_windows() -> None:
    if os.name != "nt":
        raise OSError("Windows Data Protection API is available only on Windows.")


def _blob(data: bytes):
    buffer = ctypes.create_string_buffer(data)
    blob = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    return blob, buffer


def _release(blob: _DataBlob) -> None:
    if blob.pbData:
        ctypes.windll.kernel32.LocalFree(blob.pbData)


def protect_secret(secret: str) -> bytes:
    """Protect a secret for the current Windows user with DPAPI."""
    _require_windows()
    source, source_buffer = _blob(secret.encode("utf-8"))
    destination = _DataBlob()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(source), "BaseSentinel agent credential", None, None, None, 0,
        ctypes.byref(destination),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        _release(destination)


def unprotect_secret(encrypted: bytes) -> str:
    """Decrypt a DPAPI-protected secret for the current Windows user."""
    _require_windows()
    source, source_buffer = _blob(encrypted)
    destination = _DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(source), None, None, None, None, 0, ctypes.byref(destination),
    ):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(destination.pbData, destination.cbData).decode("utf-8")
    finally:
        _release(destination)
