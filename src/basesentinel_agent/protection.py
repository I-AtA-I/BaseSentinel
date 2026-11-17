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


def _api():
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob), wintypes.LPCWSTR, ctypes.POINTER(_DataBlob),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob), ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return crypt32, kernel32


def _release(blob: _DataBlob, kernel32) -> None:
    if blob.pbData:
        kernel32.LocalFree(ctypes.cast(blob.pbData, ctypes.c_void_p))


def protect_secret(secret: str) -> bytes:
    """Protect a secret for the current Windows user with DPAPI."""
    _require_windows()
    crypt32, kernel32 = _api()
    source, source_buffer = _blob(secret.encode("utf-8"))
    destination = _DataBlob()
    if not crypt32.CryptProtectData(
        ctypes.byref(source), "BaseSentinel agent credential", None, None, None, 0,
        ctypes.byref(destination),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        _release(destination, kernel32)


def unprotect_secret(encrypted: bytes) -> str:
    """Decrypt a DPAPI-protected secret for the current Windows user."""
    _require_windows()
    crypt32, kernel32 = _api()
    source, source_buffer = _blob(encrypted)
    destination = _DataBlob()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(source), None, None, None, None, 0, ctypes.byref(destination),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(destination.pbData, destination.cbData).decode("utf-8")
    finally:
        _release(destination, kernel32)
