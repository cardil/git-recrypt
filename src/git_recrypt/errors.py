"""Typed error hierarchy for git-recrypt."""

from __future__ import annotations

from typing import override


class GitRecryptError(Exception):
    """Base error for git-recrypt."""


class ManifestError(GitRecryptError):
    """Error parsing or validating manifest."""

    __slots__: tuple[str, str] = ("detail", "path")

    detail: str
    path: str | None

    def __init__(self, detail: str, path: str | None = None) -> None:
        """Initialize ManifestError.

        Args:
            detail: Human-readable description of the error.
            path: Optional path to the manifest file that caused the error.
        """
        self.detail = detail
        self.path = path
        super().__init__(str(self))

    @override
    def __str__(self) -> str:
        """Return readable error message."""
        if self.path:
            return f"Manifest error at {self.path}: {self.detail}"
        return f"Manifest error: {self.detail}"


class CryptoError(GitRecryptError):
    """Error during encryption/decryption."""

    __slots__: tuple[str, str] = ("detail", "stderr")

    detail: str
    stderr: str | None

    def __init__(self, detail: str, stderr: str | None = None) -> None:
        """Initialize CryptoError.

        Args:
            detail: Human-readable description of the error.
            stderr: Optional stderr output from the crypto operation.
        """
        self.detail = detail
        self.stderr = stderr
        super().__init__(str(self))

    @override
    def __str__(self) -> str:
        """Return readable error message."""
        if self.stderr:
            return f"Crypto error: {self.detail}\nstderr: {self.stderr}"
        return f"Crypto error: {self.detail}"


class RewriteError(GitRecryptError):
    """Error during history rewrite."""

    __slots__: tuple[str, str] = ("detail", "phase")

    phase: str
    detail: str

    def __init__(self, phase: str, detail: str) -> None:
        """Initialize RewriteError.

        Args:
            phase: The rewrite phase where the error occurred.
            detail: Human-readable description of the error.
        """
        self.phase = phase
        self.detail = detail
        super().__init__(str(self))

    @override
    def __str__(self) -> str:
        """Return readable error message."""
        return f"Rewrite error in phase '{self.phase}': {self.detail}"


class VerifyError(GitRecryptError):
    """Verification failure."""

    __slots__: tuple[str, str] = ("detail", "filepath")

    detail: str
    filepath: str | None

    def __init__(self, detail: str, filepath: str | None = None) -> None:
        """Initialize VerifyError.

        Args:
            detail: Human-readable description of the verification failure.
            filepath: Optional path to the file that failed verification.
        """
        self.detail = detail
        self.filepath = filepath
        super().__init__(str(self))

    @override
    def __str__(self) -> str:
        """Return readable error message."""
        if self.filepath:
            return f"Verification failed for {self.filepath}: {self.detail}"
        return f"Verification failed: {self.detail}"


class DetectionError(GitRecryptError):
    """Error during secret detection."""

    __slots__: tuple[str, str] = ("detail", "profile")

    profile: str
    detail: str

    def __init__(self, profile: str, detail: str) -> None:
        """Initialize DetectionError.

        Args:
            profile: The detection profile that encountered the error.
            detail: Human-readable description of the error.
        """
        self.profile = profile
        self.detail = detail
        super().__init__(str(self))

    @override
    def __str__(self) -> str:
        """Return readable error message."""
        return f"Detection error in profile '{self.profile}': {self.detail}"
