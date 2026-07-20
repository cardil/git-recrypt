"""Manifest parsing and validation for git-recrypt."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar, Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

if TYPE_CHECKING:
    from pathlib import Path

from git_recrypt.errors import ManifestError


class SymmetricKeyConfig(BaseModel):
    """Symmetric key configuration."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    key_file: str  # Path to existing key, or "generate"
    export_to: str = "./git-crypt.key"


class GpgGenerateConfig(BaseModel):
    """GPG key generation configuration."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    name: str = "git-recrypt"
    email: str = "git-crypt@localhost"
    algorithm: str = "ed25519"
    expire: str = "0"
    passphrase: Literal["provided", "random"] = "provided"  # noqa: S105


class GpgKeyConfig(BaseModel):
    """GPG key configuration."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    user_ids: list[str] | None = None
    generate: GpgGenerateConfig | None = None


class KeyConfig(BaseModel):
    """Key configuration -- exactly one of symmetric or gpg."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    symmetric: SymmetricKeyConfig | None = None
    gpg: GpgKeyConfig | None = None

    @model_validator(mode="after")
    def _exactly_one_key_type(self) -> KeyConfig:
        has_symmetric = self.symmetric is not None
        has_gpg = self.gpg is not None
        if has_symmetric == has_gpg:  # both True or both False
            msg = "Exactly one of 'symmetric' or 'gpg' must be specified"
            raise ValueError(msg)
        return self


_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_VALID_INTRODUCE_AT = frozenset({"root", "first-match"})


class Manifest(BaseModel):
    """git-recrypt manifest -- the single input to the rewrite operation."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)

    version: Literal[1]
    key: KeyConfig
    patterns: list[str]
    named_patterns: dict[str, list[str]] | None = None
    introduce_at: str = "root"
    branches: list[str] = ["HEAD"]
    exclude: list[str] = []
    detection_profile: Literal["generic", "etckeeper", "kubernetes"] | None = None

    @model_validator(mode="after")
    def _validate_patterns_nonempty(self) -> Manifest:
        if not self.patterns:
            msg = "'patterns' must contain at least one entry"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _validate_introduce_at(self) -> Manifest:
        val = self.introduce_at
        if val not in _VALID_INTRODUCE_AT and not _SHA_PATTERN.match(val):
            msg = (
                f"'introduce_at' must be 'root', 'first-match', or a 40-char hex SHA,"
                f" got: {val}"
            )
            raise ValueError(msg)
        return self


def load_manifest(path: Path) -> Manifest:
    """Load and validate manifest from YAML file."""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ManifestError(detail="Manifest file not found", path=str(path)) from None
    except OSError as exc:
        raise ManifestError(detail=str(exc), path=str(path)) from exc

    try:
        parsed: object = yaml.safe_load(raw)  # pyright: ignore[reportAny]
    except yaml.YAMLError as exc:
        raise ManifestError(detail=f"Invalid YAML: {exc}", path=str(path)) from exc

    if not isinstance(parsed, dict):
        raise ManifestError(detail="Manifest must be a YAML mapping", path=str(path))

    try:
        return Manifest.model_validate(parsed)
    except Exception as exc:
        raise ManifestError(detail=str(exc), path=str(path)) from exc


def save_manifest(manifest: Manifest, path: Path) -> None:
    """Save manifest to YAML file."""
    data = manifest.model_dump(exclude_none=True)
    content = yaml.dump(data, default_flow_style=False, sort_keys=False)
    _ = path.write_text(content, encoding="utf-8")
