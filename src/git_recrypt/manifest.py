"""Manifest parsing and validation for git-recrypt."""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar, Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from git_recrypt.errors import ManifestError


class SymmetricKeyConfig(BaseModel):
    """Symmetric key configuration."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    key_file: str  # Path to existing key, or "generate"
    export_to: str = "./git-crypt.key"


class GpgGenerateConfig(BaseModel):
    """GPG key generation configuration."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    name: str = "git-recrypt"
    email: str = "git-crypt@localhost"
    algorithm: str = "ed25519"
    expire: str = "0"
    passphrase: Literal["provided", "random"] = "provided"  # noqa: S105


class GpgKeyConfig(BaseModel):
    """GPG key configuration."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    user_ids: list[str] | None = None
    generate: GpgGenerateConfig | None = None

    @model_validator(mode="after")
    def _validate_gpg_mode(self) -> GpgKeyConfig:
        if self.user_ids is not None and self.generate is not None:
            msg = "Exactly one of 'user_ids' or 'generate' must be specified, not both"
            raise ValueError(msg)
        if self.user_ids is None and self.generate is None:
            msg = "GPG key config must specify either 'user_ids' or 'generate'"
            raise ValueError(msg)
        if self.user_ids is not None and len(self.user_ids) == 0:
            msg = "'user_ids' must not be empty; provide at least one GPG user ID"
            raise ValueError(msg)
        return self


class KeyConfig(BaseModel):
    """Key configuration -- exactly one of symmetric or gpg."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

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

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1]
    key: KeyConfig
    patterns: list[str]
    named_patterns: dict[str, list[str]] | None = None
    repo: str = "./"
    introduce_at: str = "root"
    branches: list[str] = ["HEAD"]
    exclude: list[str] = []
    detection_profile: Literal["generic", "etckeeper", "kubernetes"] | None = None

    @model_validator(mode="after")
    def _validate_named_patterns_not_supported(self) -> Manifest:
        if self.named_patterns is not None:
            msg = "'named_patterns' is a planned feature, not yet implemented"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _validate_patterns_nonempty(self) -> Manifest:
        if not self.patterns:
            msg = "'patterns' must contain at least one entry"
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _validate_introduce_at(self) -> Manifest:
        val = self.introduce_at
        if val != "root":
            if val == "first-match" or _SHA_PATTERN.match(val):
                msg = (
                    f"'introduce_at: {val}' is not yet implemented."
                    " Only 'root' is currently supported."
                )
            else:
                msg = (
                    f"'introduce_at' must be 'root', got: {val}."
                    " 'first-match' and SHA-based introduction points"
                    " are planned but not yet implemented."
                )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def _validate_single_branch(self) -> Manifest:
        if len(self.branches) > 1:
            msg = (
                "Multi-branch rewriting is not yet implemented."
                " Only a single branch is currently supported."
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


def resolve_repo_path(
    manifest: Manifest, manifest_path: Path, cli_repo: str | None = None
) -> Path:
    """Resolve the target repo path.

    Priority: CLI --repo flag > manifest repo field > default ('./').
    Manifest-relative paths are resolved against the manifest's parent directory.
    """
    if cli_repo is not None:
        return Path(cli_repo).resolve()
    repo_str = manifest.repo
    repo_path = Path(repo_str)
    if repo_path.is_absolute():
        return repo_path
    return (manifest_path.parent / repo_path).resolve()


def save_manifest(manifest: Manifest, path: Path) -> None:
    """Save manifest to YAML file."""
    data = manifest.model_dump(exclude_none=True)
    content = yaml.dump(data, default_flow_style=False, sort_keys=False)
    _ = path.write_text(content, encoding="utf-8")
