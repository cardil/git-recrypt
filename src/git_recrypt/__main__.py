"""Entry point for `python -m git_recrypt`."""

import sys

try:
    from git_recrypt.cli import app
except ImportError:
    print(  # noqa: T201
        "git-recrypt CLI not yet fully installed. Run `uv sync` first.",
        file=sys.stderr,
    )
    sys.exit(1)
else:
    app()
