"""Pattern matching for .gitattributes-style glob patterns."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pathspec

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


@dataclass(frozen=True, slots=True)
class PatternMatcher:
    """Matches file paths against gitattributes-style glob patterns."""

    include_patterns: tuple[str, ...]
    exclude_patterns: tuple[str, ...]

    def matches(self, filepath: str) -> bool:
        """Return True if filepath matches include patterns and not exclude patterns.

        Uses pathspec with 'gitwildmatch' style.

        Args:
            filepath: The file path to test.

        Returns:
            True if the path is included and not excluded.
        """
        include_spec = pathspec.PathSpec.from_lines("gitignore", self.include_patterns)
        exclude_spec = pathspec.PathSpec.from_lines("gitignore", self.exclude_patterns)
        included = include_spec.match_file(filepath)
        excluded = exclude_spec.match_file(filepath)
        return included and not excluded

    def matches_bytes(self, filepath: bytes) -> bool:
        """Match against a bytes filepath (git-filter-repo uses bytes).

        Args:
            filepath: The file path as bytes.

        Returns:
            True if the decoded path matches.
        """
        decoded = filepath.decode("utf-8", errors="surrogateescape")
        return self.matches(decoded)

    def filter_paths(self, paths: Sequence[str]) -> list[str]:
        """Return only paths that match.

        Args:
            paths: Sequence of file paths to filter.

        Returns:
            List of paths that match the include/exclude patterns.
        """
        return [p for p in paths if self.matches(p)]


def generate_gitattributes(
    patterns: Sequence[str],
    named_patterns: Mapping[str, Sequence[str]] | None = None,
) -> str:
    """Generate .gitattributes content from pattern list.

    Each pattern becomes: <pattern> filter=git-crypt diff=git-crypt
    Named patterns use: <pattern> filter=git-crypt-<name> diff=git-crypt-<name>
    Always appends: .gitattributes !filter !diff

    Args:
        patterns: Sequence of glob patterns for the default git-crypt key.
        named_patterns: Optional mapping of key name to patterns for named keys.

    Returns:
        String content suitable for writing to .gitattributes.
    """
    lines: list[str] = [
        f"{pattern} filter=git-crypt diff=git-crypt" for pattern in patterns
    ]

    if named_patterns:
        for name, name_pats in named_patterns.items():
            lines.extend(
                f"{pattern} filter=git-crypt-{name} diff=git-crypt-{name}"
                for pattern in name_pats
            )

    lines.append(".gitattributes !filter !diff")
    return "\n".join(lines) + "\n"


def parse_gitattributes(content: str) -> list[str]:
    """Extract encryption patterns from .gitattributes content.

    Returns list of patterns that have filter=git-crypt attribute.
    Skips comments and lines without git-crypt filter.

    Args:
        content: The full text of a .gitattributes file.

    Returns:
        List of patterns with the default git-crypt filter (not named keys).
    """
    result: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:  # noqa: PLR2004
            continue
        pattern = parts[0]
        attrs = parts[1:]
        # Match only the default git-crypt filter (not git-crypt-<name>)
        if "filter=git-crypt" in attrs and "diff=git-crypt" in attrs:
            result.append(pattern)
    return result
