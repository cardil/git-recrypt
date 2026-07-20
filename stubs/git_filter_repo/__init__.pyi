from collections.abc import Callable
from typing import Any

class FileChange:
    type: bytes
    filename: bytes
    mode: bytes
    blob_id: bytes | int
    def __init__(
        self,
        type_: bytes,
        filename: bytes | None = ...,
        id_: bytes | int | None = ...,
        mode: bytes | None = ...,
    ) -> None: ...

class Commit:
    branch: bytes
    author_name: bytes
    author_email: bytes
    author_date: bytes
    committer_name: bytes
    committer_email: bytes
    committer_date: bytes
    message: bytes
    file_changes: list[FileChange]
    parents: list[int]
    original_id: bytes | None

class FileInfoValueHelper:
    def get_contents_by_identifier(self, blobhash: bytes | int) -> bytes | None: ...
    def insert_file_with_contents(self, contents: bytes) -> int: ...

class FilteringOptions:
    force: bool
    partial: bool
    source: bytes | None
    target: bytes | None
    @staticmethod
    def default_options() -> FilteringOptions: ...
    @staticmethod
    def parse_args(
        input_args: list[str], error_on_empty: bool = ...
    ) -> FilteringOptions: ...

class RepoFilter:
    def __init__(
        self,
        args: FilteringOptions,
        filename_callback: Callable[..., Any] | None = ...,
        message_callback: Callable[..., Any] | None = ...,
        name_callback: Callable[..., Any] | None = ...,
        email_callback: Callable[..., Any] | None = ...,
        refname_callback: Callable[..., Any] | None = ...,
        blob_callback: Callable[..., Any] | None = ...,
        commit_callback: Callable[[Commit, Any], None] | None = ...,
        tag_callback: Callable[..., Any] | None = ...,
        reset_callback: Callable[..., Any] | None = ...,
        done_callback: Callable[..., Any] | None = ...,
        file_info_callback: (
            Callable[
                [bytes, bytes, bytes | int, FileInfoValueHelper],
                tuple[bytes, bytes, bytes | int],
            ]
            | None
        ) = ...,
    ) -> None: ...
    def run(self) -> None: ...
