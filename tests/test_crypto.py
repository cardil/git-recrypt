"""Tests for git_recrypt.crypto -- TDD, Given/When/Then."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from git_recrypt.crypto import GITCRYPT_HEADER, CryptoEngine, is_encrypted
from git_recrypt.errors import CryptoError

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# is_encrypted() -- pure function, no fixture needed
# ---------------------------------------------------------------------------


def test_is_encrypted_true() -> None:
    """Given GITCRYPT header data, when is_encrypted called, returns True."""
    # Given
    data = GITCRYPT_HEADER + b"some encrypted payload"
    # When / Then
    assert is_encrypted(data) is True


def test_is_encrypted_false() -> None:
    """Given plaintext data, when is_encrypted called, returns False."""
    # Given
    data = b"hello world"
    # When / Then
    assert is_encrypted(data) is False


# ---------------------------------------------------------------------------
# CryptoEngine construction
# ---------------------------------------------------------------------------


def test_missing_key_file_raises(tmp_path: Path) -> None:
    """Given missing key file, when CryptoEngine constructed, raises CryptoError."""
    # Given
    missing = tmp_path / "does_not_exist.key"
    # When / Then
    with pytest.raises(CryptoError, match="Key file not found"):
        CryptoEngine(key_file=missing)


# ---------------------------------------------------------------------------
# encrypt / decrypt -- require a real key file
# ---------------------------------------------------------------------------


def test_encrypt_produces_header(sample_key_file: Path) -> None:
    """Given plaintext, when encrypted, output starts with GITCRYPT header."""
    # Given
    engine = CryptoEngine(key_file=sample_key_file)
    plaintext = b"hello world"
    # When
    encrypted = engine.encrypt(plaintext)
    # Then
    assert encrypted[:10] == GITCRYPT_HEADER


def test_roundtrip_decrypt(sample_key_file: Path) -> None:
    """Given plaintext, when encrypted then decrypted, result equals original."""
    # Given
    engine = CryptoEngine(key_file=sample_key_file)
    plaintext = b"hello world"
    # When
    encrypted = engine.encrypt(plaintext)
    decrypted = engine.decrypt(encrypted)
    # Then
    assert decrypted == plaintext


def test_encrypt_idempotent(sample_key_file: Path) -> None:
    """Given already-encrypted data, when encrypted again, returns same bytes."""
    # Given
    engine = CryptoEngine(key_file=sample_key_file)
    plaintext = b"idempotent test"
    encrypted_once = engine.encrypt(plaintext)
    # When
    encrypted_twice = engine.encrypt(encrypted_once)
    # Then
    assert encrypted_twice == encrypted_once


def test_empty_file_roundtrip(sample_key_file: Path) -> None:
    """Given empty bytes, when encrypted then decrypted, result is empty bytes."""
    # Given
    engine = CryptoEngine(key_file=sample_key_file)
    plaintext = b""
    # When
    encrypted = engine.encrypt(plaintext)
    decrypted = engine.decrypt(encrypted)
    # Then
    assert decrypted == plaintext


def test_binary_data_roundtrip(sample_key_file: Path) -> None:
    """Given binary data with nulls and high bytes, roundtrip matches."""
    # Given
    engine = CryptoEngine(key_file=sample_key_file)
    plaintext = bytes(range(256)) * 4  # all byte values, repeated
    # When
    encrypted = engine.encrypt(plaintext)
    decrypted = engine.decrypt(encrypted)
    # Then
    assert decrypted == plaintext


def test_large_file_roundtrip(sample_key_file: Path) -> None:
    """Given 1MB of pseudo-random data, roundtrip matches original."""
    # Given
    engine = CryptoEngine(key_file=sample_key_file)
    # Deterministic pseudo-random: cycle through all byte values
    plaintext = bytes(i % 256 for i in range(1024 * 1024))
    # When
    encrypted = engine.encrypt(plaintext)
    decrypted = engine.decrypt(encrypted)
    # Then
    assert decrypted == plaintext


def test_verify_roundtrip_returns_true(sample_key_file: Path) -> None:
    """Given plaintext, when verify_roundtrip called, returns True."""
    # Given
    engine = CryptoEngine(key_file=sample_key_file)
    plaintext = b"verify me"
    # When
    result = engine.verify_roundtrip(plaintext)
    # Then
    assert result is True
