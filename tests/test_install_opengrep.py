"""Tests for the Opengrep installer's signature verification and asset selection.

install_opengrep.py downloads a platform binary and, when cosign is
available, verifies it against Sigstore's cosign signature before
installing. It no longer touches tarfile/zipfile at all -- every platform
now uses a raw signed binary asset, which removes the tar-slip/zip-slip
extraction surface entirely rather than just mitigating it.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from rowan.install_opengrep import (
    PINNED_SHA256,
    PINNED_VERSION,
    SignatureVerificationError,
    _detect_asset_name,
    install,
    verify_signature,
)

_FAKE_RELEASE = {
    "tag_name": "v1.24.0",
    "assets": [
        {"name": "opengrep_manylinux_x86", "browser_download_url": "https://example.test/opengrep_manylinux_x86"},
        {"name": "opengrep_manylinux_x86.sig", "browser_download_url": "https://example.test/opengrep_manylinux_x86.sig"},
        {"name": "opengrep_manylinux_x86.cert", "browser_download_url": "https://example.test/opengrep_manylinux_x86.cert"},
    ],
}


def _fake_download(_url: str, dest) -> None:
    dest.write_bytes(b"fake-binary-contents")


class TestDetectAssetName:
    def test_darwin_arm64(self):
        with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="arm64"):
            assert _detect_asset_name() == "opengrep_osx_arm64"

    def test_darwin_x86(self):
        with patch("platform.system", return_value="Darwin"), patch("platform.machine", return_value="x86_64"):
            assert _detect_asset_name() == "opengrep_osx_x86"

    def test_linux_aarch64(self):
        with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="aarch64"):
            assert _detect_asset_name() == "opengrep_manylinux_aarch64"

    def test_linux_x86(self):
        with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
            assert _detect_asset_name() == "opengrep_manylinux_x86"

    def test_windows(self):
        with patch("platform.system", return_value="Windows"), patch("platform.machine", return_value="AMD64"):
            assert _detect_asset_name() == "opengrep_windows_x86.exe"

    def test_no_archive_extensions_selected(self):
        """Every platform must resolve to a raw binary, never .tar.gz/.zip --
        those variants have no published .sig/.cert and required archive
        extraction (the tar-slip/zip-slip surface this fix removes)."""
        for system, machine in [("Darwin", "arm64"), ("Linux", "x86_64"), ("Windows", "AMD64")]:
            with patch("platform.system", return_value=system), patch("platform.machine", return_value=machine):
                name = _detect_asset_name()
                assert not name.endswith((".tar.gz", ".zip"))


class TestVerifySignature:
    def test_cosign_success(self, tmp_path):
        binary = tmp_path / "opengrep"
        binary.write_bytes(b"x")
        sig = tmp_path / "opengrep.sig"
        sig.write_text("sig")
        cert = tmp_path / "opengrep.cert"
        cert.write_text("cert")

        fake_result = MagicMock(returncode=0, stderr="")
        with patch("subprocess.run", return_value=fake_result) as mock_run:
            verify_signature(binary, sig, cert)
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "cosign"
        assert "--certificate-oidc-issuer" in args

    def test_cosign_failure_raises(self, tmp_path):
        binary = tmp_path / "opengrep"
        binary.write_bytes(b"x")
        sig = tmp_path / "opengrep.sig"
        sig.write_text("sig")
        cert = tmp_path / "opengrep.cert"
        cert.write_text("cert")

        fake_result = MagicMock(returncode=1, stderr="signature mismatch")
        with patch("subprocess.run", return_value=fake_result), pytest.raises(SignatureVerificationError):
            verify_signature(binary, sig, cert)


class TestInstallSignatureGating:
    def test_install_verifies_when_cosign_available(self, tmp_path):
        with patch("rowan.install_opengrep._fetch_release_info", return_value=_FAKE_RELEASE), \
             patch("rowan.install_opengrep._download", side_effect=_fake_download), \
             patch("shutil.which", return_value="/usr/bin/cosign"), \
             patch("rowan.install_opengrep.verify_signature") as mock_verify, \
             patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
            install(tmp_path, version="v1.24.0")
        mock_verify.assert_called_once()
        assert (tmp_path / "bin" / "opengrep").exists()

    def test_install_fails_closed_when_verification_fails(self, tmp_path):
        with patch("rowan.install_opengrep._fetch_release_info", return_value=_FAKE_RELEASE), \
             patch("rowan.install_opengrep._download", side_effect=_fake_download), \
             patch("shutil.which", return_value="/usr/bin/cosign"), \
             patch(
                 "rowan.install_opengrep.verify_signature",
                 side_effect=SignatureVerificationError("bad signature"),
             ), \
             patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"), \
             pytest.raises(SignatureVerificationError):
            install(tmp_path, version="v1.24.0")
        # Verification failure must happen before the binary is installed.
        assert not (tmp_path / "bin" / "opengrep").exists()

    def test_install_refuses_by_default_without_cosign(self, tmp_path):
        """Issue #224: signature verification must be required by default,
        not opt-in. Missing cosign must fail closed unless the caller
        explicitly passes require_signature=False."""
        with patch("rowan.install_opengrep._fetch_release_info") as mock_fetch, \
             patch("rowan.install_opengrep._download") as mock_download, \
             patch("shutil.which", return_value=None), \
             patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"), \
             pytest.raises(RuntimeError, match="cosign is not installed"):
            install(tmp_path, version="v1.24.0")
        mock_fetch.assert_not_called()
        mock_download.assert_not_called()
        assert not (tmp_path / "bin").exists()
        assert not (tmp_path / "bin" / "opengrep").exists()

    def test_install_allow_unverified_warns_and_proceeds_without_cosign(self, tmp_path, capsys):
        with patch("rowan.install_opengrep._fetch_release_info", return_value=_FAKE_RELEASE), \
             patch("rowan.install_opengrep._download", side_effect=_fake_download), \
             patch("shutil.which", return_value=None), \
             patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
            install(tmp_path, require_signature=False, version="v1.24.0")
        assert (tmp_path / "bin" / "opengrep").exists()
        assert "cosign is not installed" in capsys.readouterr().err

    def test_install_refuses_by_default_without_sig_assets(self, tmp_path):
        release_no_sig = {
            "tag_name": "v1.24.0",
            "assets": [
                {"name": "opengrep_manylinux_x86", "browser_download_url": "https://example.test/opengrep_manylinux_x86"},
            ],
        }
        with patch("rowan.install_opengrep._fetch_release_info", return_value=release_no_sig), \
             patch("rowan.install_opengrep._download", side_effect=_fake_download), \
             patch("shutil.which", return_value="/usr/bin/cosign"), \
             patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"), \
             pytest.raises(RuntimeError, match=r"no \.sig/\.cert assets"):
            install(tmp_path, version="v1.24.0")
        assert not (tmp_path / "bin" / "opengrep").exists()

    def test_install_allow_unverified_warns_and_proceeds_without_sig_assets(self, tmp_path, capsys):
        release_no_sig = {
            "tag_name": "v1.24.0",
            "assets": [
                {"name": "opengrep_manylinux_x86", "browser_download_url": "https://example.test/opengrep_manylinux_x86"},
            ],
        }
        with patch("rowan.install_opengrep._fetch_release_info", return_value=release_no_sig), \
             patch("rowan.install_opengrep._download", side_effect=_fake_download), \
             patch("shutil.which", return_value="/usr/bin/cosign"), \
             patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
            install(tmp_path, require_signature=False, version="v1.24.0")
        assert (tmp_path / "bin" / "opengrep").exists()
        assert "no .sig/.cert assets" in capsys.readouterr().err

    def test_install_chmod_is_owner_only(self, tmp_path):
        """Issue #224: the binary must not be group/other executable."""
        import stat

        with patch("rowan.install_opengrep._fetch_release_info", return_value=_FAKE_RELEASE), \
             patch("rowan.install_opengrep._download", side_effect=_fake_download), \
             patch("shutil.which", return_value="/usr/bin/cosign"), \
             patch("rowan.install_opengrep.verify_signature"), \
             patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
            binary_path = install(tmp_path, version="v1.24.0")
        mode = stat.S_IMODE(binary_path.stat().st_mode)
        assert mode == (stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def test_install_version_is_passed_through_to_fetch(self, tmp_path):
        """Issue #224: --version must pin a specific release, not always latest."""
        with patch("rowan.install_opengrep._fetch_release_info", return_value=_FAKE_RELEASE) as mock_fetch, \
             patch("rowan.install_opengrep._download", side_effect=_fake_download), \
             patch("shutil.which", return_value="/usr/bin/cosign"), \
             patch("rowan.install_opengrep.verify_signature"), \
             patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
            install(tmp_path, version="v1.24.0")
        mock_fetch.assert_called_once_with("v1.24.0")


class TestDownloadURLAllowlist:
    """Issue #224: no scheme or host allowlist on the download URL meant
    file:// and ftp:// were accepted, and any https host would do."""

    def test_file_scheme_rejected(self, tmp_path):
        from rowan.install_opengrep import _download

        with pytest.raises(RuntimeError, match="Refusing to download"):
            _download("file:///etc/passwd", tmp_path / "out")
        assert not (tmp_path / "out").exists()

    def test_ftp_scheme_rejected(self, tmp_path):
        from rowan.install_opengrep import _download

        with pytest.raises(RuntimeError, match="Refusing to download"):
            _download("ftp://evil.example/opengrep", tmp_path / "out")
        assert not (tmp_path / "out").exists()

    def test_https_to_non_allowlisted_host_rejected(self, tmp_path):
        from rowan.install_opengrep import _download

        with pytest.raises(RuntimeError, match="Refusing to download"):
            _download("https://evil.example/opengrep", tmp_path / "out")
        assert not (tmp_path / "out").exists()


def test_download_rejects_offhost_redirect():
    """PL-16: every redirect target must pass the same host allowlist."""
    import urllib.request

    import pytest

    from rowan import install_opengrep

    handler = install_opengrep._AllowlistedRedirects()
    req = urllib.request.Request("https://github.com/opengrep/opengrep/releases/download/v1/x")
    with pytest.raises(RuntimeError, match=r"evil\.example"):
        handler.redirect_request(req, None, 302, "Found", {}, "https://evil.example/x")
    # GitHub's real asset CDN is allowed.
    ok = handler.redirect_request(
        req, None, 302, "Found", {}, "https://release-assets.githubusercontent.com/github-production-release-asset/1/2"
    )
    assert ok.full_url.startswith("https://release-assets.githubusercontent.com/")


def test_download_uses_a_timeout_and_the_redirect_check(tmp_path, monkeypatch):
    from rowan import install_opengrep

    seen = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, n=-1):
            data, self._data = getattr(self, "_data", b"binary"), b""
            return data

    class _Opener:
        def open(self, url, timeout=None):
            seen["timeout"] = timeout
            return _Resp()

    def build_opener(*handlers):
        seen["handlers"] = handlers
        return _Opener()

    monkeypatch.setattr(install_opengrep.urllib.request, "build_opener", build_opener)
    dest = tmp_path / "bin"
    install_opengrep._download("https://github.com/opengrep/opengrep/releases/download/v1/x", dest)
    assert dest.read_bytes() == b"binary"
    assert seen["timeout"] and seen["timeout"] > 0
    assert any(h is install_opengrep._AllowlistedRedirects for h in seen["handlers"])


def test_windows_binary_keeps_exe_suffix(tmp_path, monkeypatch):
    """PL-17: on Windows the installed binary must be opengrep.exe."""
    from rowan import install_opengrep

    asset = "opengrep_windows_x86.exe"
    monkeypatch.setattr(install_opengrep.platform, "system", lambda: "Windows")
    monkeypatch.setattr(install_opengrep, "_detect_asset_name", lambda: asset)
    monkeypatch.setattr(install_opengrep, "_fetch_release_info", lambda version: {
        "tag_name": "v1", "assets": [{"name": asset, "browser_download_url": "https://github.com/x/y"}],
    })
    monkeypatch.setattr(install_opengrep, "_download", lambda url, dest: dest.write_bytes(b"MZ"))
    monkeypatch.setattr(install_opengrep.shutil, "which", lambda name: None)

    path = install_opengrep.install(tmp_path, require_signature=False, version="v1")

    assert path.name == "opengrep.exe"
    assert path.read_bytes() == b"MZ"


_PINNED_RELEASE = {
    "tag_name": PINNED_VERSION,
    "assets": [{"name": "opengrep_manylinux_x86",
                "browser_download_url": "https://example.test/opengrep_manylinux_x86"}],
}


class TestPinnedVersionNeedsNoCosign:
    """The default engine version is verified against SHA-256 hashes shipped
    in Rowan, so a first install needs no cosign. Each hash was checked
    against Opengrep's Sigstore signature when it was pinned."""

    def _linux(self):
        return patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64")

    def test_matching_hash_installs_without_cosign(self, tmp_path, monkeypatch):
        body = b"genuine-engine"
        import hashlib
        monkeypatch.setitem(PINNED_SHA256, "opengrep_manylinux_x86", hashlib.sha256(body).hexdigest())
        s, m = self._linux()
        with patch("rowan.install_opengrep._fetch_release_info", return_value=_PINNED_RELEASE), \
             patch("rowan.install_opengrep._download", side_effect=lambda _u, d: d.write_bytes(body)), \
             patch("shutil.which", return_value=None), s, m:
            install(tmp_path)
        assert (tmp_path / "bin" / "opengrep").read_bytes() == body

    def test_mismatched_hash_never_installs_even_when_unverified_allowed(self, tmp_path):
        s, m = self._linux()
        with patch("rowan.install_opengrep._fetch_release_info", return_value=_PINNED_RELEASE), \
             patch("rowan.install_opengrep._download", side_effect=_fake_download), \
             patch("shutil.which", return_value=None), s, m, \
             pytest.raises(SignatureVerificationError, match="SHA-256"):
            install(tmp_path, require_signature=False)
        assert not (tmp_path / "bin" / "opengrep").exists()

    def test_release_tag_must_match_the_pin(self, tmp_path):
        s, m = self._linux()
        wrong = {**_PINNED_RELEASE, "tag_name": "v9.9.9"}
        with patch("rowan.install_opengrep._fetch_release_info", return_value=wrong), \
             patch("rowan.install_opengrep._download", side_effect=_fake_download), \
             patch("shutil.which", return_value=None), s, m, \
             pytest.raises(RuntimeError, match="expected"):
            install(tmp_path)

    def test_latest_is_an_explicit_unpinned_choice(self, tmp_path):
        s, m = self._linux()
        with patch("rowan.install_opengrep._fetch_release_info", return_value=_FAKE_RELEASE) as mock_fetch, \
             patch("rowan.install_opengrep._download", side_effect=_fake_download), \
             patch("shutil.which", return_value="/usr/bin/cosign"), \
             patch("rowan.install_opengrep.verify_signature") as mock_verify, s, m:
            install(tmp_path, version="latest")
        mock_fetch.assert_called_once_with(None)
        mock_verify.assert_called_once()

    def test_every_supported_platform_has_a_pinned_hash(self):
        assets = {"opengrep_osx_arm64", "opengrep_osx_x86", "opengrep_windows_x86.exe",
                  "opengrep_manylinux_aarch64", "opengrep_manylinux_x86"}
        assert set(PINNED_SHA256) == assets
        assert all(len(h) == 64 and int(h, 16) >= 0 for h in PINNED_SHA256.values())


class TestReleaseApiToken:
    """CI shares GitHub's unauthenticated rate limit (60 requests an hour),
    so the release-info call sends GITHUB_TOKEN / GH_TOKEN when set. Only
    that call: asset downloads redirect to other hosts."""

    def _captured_request(self, monkeypatch):
        import io
        import json as _json

        import rowan.install_opengrep as io_mod

        seen = {}

        class FakeOpener:
            def open(self, req, timeout):
                seen["req"] = req
                return io.BytesIO(_json.dumps({"tag_name": "v1"}).encode())

        monkeypatch.setattr(io_mod.urllib.request, "build_opener", lambda *handlers: FakeOpener())
        io_mod._fetch_release_info("v1")
        return seen["req"]

    def test_github_token_is_sent(self, monkeypatch):
        monkeypatch.delenv("GH_TOKEN", raising=False)
        monkeypatch.setenv("GITHUB_TOKEN", "test-token-not-real")
        req = self._captured_request(monkeypatch)
        assert req.get_header("Authorization") == "Bearer test-token-not-real"

    def test_gh_token_is_the_fallback(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("GH_TOKEN", "test-token-not-real")
        req = self._captured_request(monkeypatch)
        assert req.get_header("Authorization") == "Bearer test-token-not-real"

    def test_no_token_no_header(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GH_TOKEN", raising=False)
        req = self._captured_request(monkeypatch)
        assert req.get_header("Authorization") is None

    def test_token_is_dropped_on_redirect_to_another_host(self):
        import urllib.request

        from rowan.install_opengrep import _DropAuthOnHostChange

        req = urllib.request.Request(
            "https://api.github.com/repos/x/y/releases/latest",
            headers={"Authorization": "Bearer test-token-not-real"},
        )
        handler = _DropAuthOnHostChange()
        same = handler.redirect_request(req, None, 301, "Moved", {}, "https://api.github.com/repositories/1/releases/latest")
        other = handler.redirect_request(req, None, 302, "Found", {}, "https://example.com/elsewhere")
        assert same.get_header("Authorization") == "Bearer test-token-not-real"
        assert other.get_header("Authorization") is None
