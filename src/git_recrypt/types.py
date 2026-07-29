"""Shared branded types for git-recrypt."""

from pathlib import Path
from typing import NewType

PatternStr = NewType("PatternStr", str)
CommitSha = NewType("CommitSha", str)
KeyFilePath = NewType("KeyFilePath", Path)
BranchName = NewType("BranchName", str)
