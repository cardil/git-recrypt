"""Root conftest: disable GPG commit signing for all tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True, scope="session")
def _disable_gpg_signing(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Override global git config to disable GPG signing in tests.

    The global git config may have commit.gpgsign=true which breaks
    git commit calls in fixtures. We point GIT_CONFIG_GLOBAL at a
    minimal config that disables signing.
    """
    cfg_dir = tmp_path_factory.mktemp("gitconfig")
    cfg_file = cfg_dir / "gitconfig"
    cfg_file.write_text(
        "[commit]\n\tgpgsign = false\n"
        "[tag]\n\tgpgsign = false\n"
        "[user]\n\tname = Test\n\temail = test@example.com\n"
    )
    os.environ["GIT_CONFIG_GLOBAL"] = str(cfg_file)
    os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
