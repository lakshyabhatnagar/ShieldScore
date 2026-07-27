"""Tests for GitHub URL parsing through the shared git URL parser."""

from app.utils.git import SOURCE_GENERIC_GIT, SOURCE_GITHUB, SOURCE_GITLAB, parse_git_url


class TestParseRepo:
    def test_https_url(self):
        owner, repo, source = parse_git_url("https://github.com/owner/repo")
        assert owner == "owner"
        assert repo == "repo"
        assert source == SOURCE_GITHUB

    def test_https_url_with_git_suffix(self):
        owner, repo, source = parse_git_url("https://github.com/owner/repo.git")
        assert owner == "owner"
        assert repo == "repo"
        assert source == SOURCE_GITHUB

    def test_ssh_url(self):
        owner, repo, source = parse_git_url("git@github.com:owner/repo.git")
        assert owner == "owner"
        assert repo == "repo"
        assert source == SOURCE_GITHUB

    def test_ssh_url_without_git_suffix(self):
        owner, repo, source = parse_git_url("git@github.com:owner/repo")
        assert owner == "owner"
        assert repo == "repo"
        assert source == SOURCE_GITHUB

    def test_gitlab_url_is_classified(self):
        owner, repo, source = parse_git_url("https://gitlab.com/owner/repo")
        assert (owner, repo, source) == ("owner", "repo", SOURCE_GITLAB)

    def test_invalid_url(self):
        owner, repo, source = parse_git_url("not-a-url")
        assert owner is None
        assert repo is None
        assert source == SOURCE_GENERIC_GIT

    def test_empty_string(self):
        owner, repo, _ = parse_git_url("")
        assert owner is None
        assert repo is None

    def test_trailing_slash(self):
        owner, repo, source = parse_git_url("https://github.com/owner/repo/")
        assert owner == "owner"
        assert repo == "repo"
        assert source == SOURCE_GITHUB
