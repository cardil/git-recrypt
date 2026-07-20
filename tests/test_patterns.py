"""Tests for git_recrypt.patterns module."""

from __future__ import annotations

from git_recrypt.patterns import (
    PatternMatcher,
    generate_gitattributes,
    parse_gitattributes,
)


def test_simple_extension_match() -> None:
    # Given a matcher for *.key
    matcher = PatternMatcher(include_patterns=("*.key",), exclude_patterns=())

    # When checking various paths
    # Then matches .key files at root and in subdirs, not .key.bak
    assert matcher.matches("foo.key")
    assert matcher.matches("dir/bar.key")
    assert not matcher.matches("foo.key.bak")
    assert not matcher.matches("foo.txt")


def test_directory_recursion() -> None:
    # Given a matcher for secrets/**
    matcher = PatternMatcher(include_patterns=("secrets/**",), exclude_patterns=())

    # When checking paths under secrets/ and unrelated paths
    # Then matches nested paths, not similarly-named files
    assert matcher.matches("secrets/a.txt")
    assert matcher.matches("secrets/sub/b.txt")
    assert not matcher.matches("secret.txt")
    assert not matcher.matches("other/secrets/a.txt")


def test_specific_file() -> None:
    # Given a matcher for .env
    matcher = PatternMatcher(include_patterns=(".env",), exclude_patterns=())

    # When checking .env at root
    # Then matches .env at root
    assert matcher.matches(".env")


def test_exclude_patterns() -> None:
    # Given a matcher that includes *.key but excludes *.pub
    matcher = PatternMatcher(include_patterns=("*.key",), exclude_patterns=("*.pub",))

    # When checking foo.key and foo.pub
    # Then foo.key matches, foo.pub does not
    assert matcher.matches("foo.key")
    assert not matcher.matches("foo.pub")
    assert not matcher.matches("foo.txt")


def test_generate_gitattributes_basic() -> None:
    # Given a list of patterns
    patterns = ["*.key", "secrets/**"]

    # When generating gitattributes content
    content = generate_gitattributes(patterns)

    # Then each pattern has the correct git-crypt attributes
    assert "*.key filter=git-crypt diff=git-crypt" in content
    assert "secrets/** filter=git-crypt diff=git-crypt" in content


def test_generate_gitattributes_always_excludes_self() -> None:
    # Given any list of patterns (even empty)
    patterns = ["*.key"]

    # When generating gitattributes content
    content = generate_gitattributes(patterns)

    # Then the last line is always the self-exclusion
    lines = [line for line in content.splitlines() if line.strip()]
    assert lines[-1] == ".gitattributes !filter !diff"


def test_parse_gitattributes_roundtrip() -> None:
    # Given a list of patterns
    patterns = ["*.key", "secrets/**", ".env"]

    # When generating then parsing
    content = generate_gitattributes(patterns)
    parsed = parse_gitattributes(content)

    # Then the original patterns are recovered
    assert parsed == patterns


def test_empty_patterns() -> None:
    # Given an empty pattern list
    patterns: list[str] = []

    # When generating gitattributes content
    content = generate_gitattributes(patterns)

    # Then only the self-exclusion line is present
    lines = [line for line in content.splitlines() if line.strip()]
    assert lines == [".gitattributes !filter !diff"]


def test_matches_bytes() -> None:
    # Given a matcher for *.key
    matcher = PatternMatcher(include_patterns=("*.key",), exclude_patterns=())

    # When matching bytes filepaths
    # Then correctly matches and rejects
    assert matcher.matches_bytes(b"foo.key")
    assert not matcher.matches_bytes(b"foo.txt")


def test_filter_paths() -> None:
    # Given a matcher for *.key
    matcher = PatternMatcher(include_patterns=("*.key",), exclude_patterns=())
    paths = ["foo.key", "bar.txt", "dir/baz.key", "qux.key.bak"]

    # When filtering a list of paths
    result = matcher.filter_paths(paths)

    # Then only matching paths are returned
    assert result == ["foo.key", "dir/baz.key"]


def test_generate_gitattributes_named_keys() -> None:
    # Given patterns and named patterns
    patterns = ["*.key"]
    named_patterns = {"backup": ["*.bak", "*.old"]}

    # When generating gitattributes content
    content = generate_gitattributes(patterns, named_patterns)

    # Then named patterns use filter=git-crypt-<name>
    assert "*.key filter=git-crypt diff=git-crypt" in content
    assert "*.bak filter=git-crypt-backup diff=git-crypt-backup" in content
    assert "*.old filter=git-crypt-backup diff=git-crypt-backup" in content
    # And self-exclusion is still present
    assert ".gitattributes !filter !diff" in content
