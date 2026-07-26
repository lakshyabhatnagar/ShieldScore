import asyncio
import io
import logging
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Source type detection
# ---------------------------------------------------------------------------

SOURCE_GITHUB = "github"
SOURCE_GITLAB = "gitlab"
SOURCE_BITBUCKET = "bitbucket"
SOURCE_GENERIC_GIT = "git"
SOURCE_ZIP = "zip"

# Limits protect the server from unexpectedly large or highly-compressed uploads.
MAX_ZIP_FILES = 10_000
MAX_ZIP_UNCOMPRESSED_BYTES = 500 * 1024 * 1024


def detect_source_type(repo_url: str) -> str:
    """Detect the type of repository source from the URL.

    Returns one of: 'github', 'gitlab', 'bitbucket', 'git', or 'zip'.
    """
    if not repo_url:
        return ""

    if repo_url.startswith("zip://"):
        return SOURCE_ZIP

    # SSH-style URLs
    if repo_url.startswith(("git@", "ssh://")):
        if "github.com" in repo_url:
            return SOURCE_GITHUB
        if "gitlab.com" in repo_url or "gitlab." in repo_url:
            return SOURCE_GITLAB
        if "bitbucket.org" in repo_url:
            return SOURCE_BITBUCKET
        return SOURCE_GENERIC_GIT

    # HTTPS URLs
    parsed = urlparse(repo_url)
    if parsed.scheme not in ("http", "https"):
        return SOURCE_GENERIC_GIT

    netloc = parsed.netloc.lower()
    if "github.com" in netloc:
        return SOURCE_GITHUB
    if "gitlab" in netloc:
        return SOURCE_GITLAB
    if "bitbucket" in netloc:
        return SOURCE_BITBUCKET

    return SOURCE_GENERIC_GIT


def parse_git_url(repo_url: str) -> tuple[str | None, str | None, str]:
    """Parse a git URL into (owner, repo, source_type).

    Supports GitHub, GitLab, Bitbucket, and generic git URLs.
    Returns (None, None, type) for URLs that can't be parsed into owner/repo.
    """
    source_type = detect_source_type(repo_url)

    if source_type == SOURCE_ZIP:
        parsed = urlparse(repo_url)
        repo_name = parsed.netloc or parsed.path.strip("/")
        return None, repo_name or None, source_type

    # SSH format: git@github.com:owner/repo.git
    ssh_match = re.match(
        r"^git@(?P<host>[^:]+):(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$",
        repo_url,
    )
    if ssh_match:
        owner = ssh_match.group("owner")
        repo = ssh_match.group("repo").removesuffix(".git")
        return owner, repo, source_type

    # Parse as URL (handles https:// and ssh:// schemes)
    parsed = urlparse(repo_url)
    if parsed.scheme not in ("http", "https", "ssh"):
        return None, None, source_type

    parts = [p for p in parsed.path.strip("/").removesuffix(".git").split("/") if p]

    if source_type in (SOURCE_GITHUB, SOURCE_GITLAB):
        if len(parts) >= 2:
            return parts[0], parts[-1], source_type
    elif source_type == SOURCE_BITBUCKET:
        # Bitbucket: /workspace/repo or /workspace/repo/src/branch
        if len(parts) >= 2:
            return parts[0], parts[1], source_type
    else:
        # Generic git — use the repo name only
        if parts:
            return None, parts[-1], source_type

    return None, None, source_type


# ---------------------------------------------------------------------------
# Git operations
# ---------------------------------------------------------------------------


def _find_git() -> str:
    """Find the git executable path."""
    git_path = shutil.which("git")
    if git_path:
        return git_path
    for candidate in [
        r"C:\Program Files\Git\bin\git.exe",
        r"C:\Program Files (x86)\Git\bin\git.exe",
        os.path.expanduser("~/scoop/shims/git.exe"),
        os.path.expanduser("~/AppData/Local/Programs/Git/bin/git.exe"),
    ]:
        if os.path.isfile(candidate):
            return candidate
    raise RuntimeError(
        "git is not installed or not on PATH. "
        "Install git from https://git-scm.com/ and ensure it's on PATH."
    )


def _clone_sync(repo_url: str, tmp_dir: str, git_path: str) -> str:
    """Synchronous git clone — runs in a thread via asyncio.to_thread."""
    result = subprocess.run(
        [git_path, "clone", "--depth", "1", repo_url, tmp_dir],
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        err = result.stderr.decode(errors="replace") if result.stderr else ""
        out = result.stdout.decode(errors="replace") if result.stdout else ""
        detail = err.strip() or out.strip() or f"git clone failed (exit code {result.returncode})"
        raise RuntimeError(detail)
    return tmp_dir


async def clone_repo(repo_url: str) -> str:
    """Clone a git repo to a temporary directory and return the path."""
    git_path = _find_git()
    tmp_dir = tempfile.mkdtemp()
    logger.debug("Cloning into %s", tmp_dir)

    await asyncio.to_thread(_clone_sync, repo_url, tmp_dir, git_path)

    logger.info("Cloned %s successfully", repo_url)
    return tmp_dir


async def cleanup_repo(path: str) -> None:
    """Remove a temporary repository directory."""
    if path:
        target = Path(path).resolve()
        temp_root = Path(tempfile.gettempdir()).resolve()
        # ZIPs commonly contain one project directory. Remove its temporary
        # extraction parent too, while never broadening cleanup beyond tmpdir.
        if target.parent.parent == temp_root and target.parent.name.startswith(tempfile.gettempprefix()):
            target = target.parent
        shutil.rmtree(target, ignore_errors=True)
        logger.debug("Cleaned up temp dir")


# ---------------------------------------------------------------------------
# ZIP extraction
# ---------------------------------------------------------------------------


async def extract_zip(zip_data: bytes) -> str:
    """Safely extract a repository ZIP to a temporary directory."""
    extract_root = tempfile.mkdtemp()

    def _extract():
        root = Path(extract_root).resolve()
        try:
            with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                members = zf.infolist()
                if len(members) > MAX_ZIP_FILES:
                    raise ValueError(f"Archive has more than {MAX_ZIP_FILES} files")
                if sum(member.file_size for member in members) > MAX_ZIP_UNCOMPRESSED_BYTES:
                    raise ValueError("Archive expands beyond the 500 MB limit")

                for member in members:
                    target = (root / member.filename).resolve()
                    if target != root and root not in target.parents:
                        raise ValueError("Archive contains an unsafe file path")
                    # Symlinks can point outside the extraction directory after unpacking.
                    if (member.external_attr >> 16) & 0o170000 == 0o120000:
                        raise ValueError("Archive contains unsupported symbolic links")

                for member in members:
                    target = root / member.filename
                    if member.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as source, target.open("wb") as destination:
                        shutil.copyfileobj(source, destination)
        except Exception:
            shutil.rmtree(extract_root, ignore_errors=True)
            raise

        entries = list(root.iterdir())
        if len(entries) == 1 and entries[0].is_dir():
            return str(entries[0])
        return extract_root

    return await asyncio.to_thread(_extract)
