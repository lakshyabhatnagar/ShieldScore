import asyncio
import io
import zipfile
from pathlib import Path

import pytest

from app.utils.git import SOURCE_ZIP, cleanup_repo, detect_source_type, extract_zip, parse_git_url


def test_zip_source_has_a_display_name():
    assert detect_source_type("zip://my-project") == SOURCE_ZIP
    assert parse_git_url("zip://my-project") == (None, "my-project", SOURCE_ZIP)


def test_extract_zip_rejects_path_traversal():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../outside.txt", "no")

    with pytest.raises(ValueError, match="unsafe file path"):
        asyncio.run(extract_zip(archive.getvalue()))


def test_extract_zip_returns_a_cleanable_root():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("project/README.md", "# Project")

    extracted = asyncio.run(extract_zip(archive.getvalue()))
    root = Path(extracted)
    try:
        assert (root / "README.md").read_text() == "# Project"
    finally:
        asyncio.run(cleanup_repo(extracted))
    assert not root.parent.exists()
