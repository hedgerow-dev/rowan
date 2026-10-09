#!/usr/bin/env python3
"""Download and install the Opengrep binary.

Usage (via the CLI):
    rowan install-engine                      # the pinned version, hash-verified
    rowan install-engine --prefix /usr/local
    rowan install-engine --version v1.14.0    # any other tag needs cosign
    rowan install-engine --version latest
    rowan install-engine --allow-unverified   # NOT recommended

The default is PINNED_VERSION, checked against SHA-256 hashes shipped in this
file, so a first install needs no extra tool. Each hash was verified against
Opengrep's Sigstore signature when it was pinned. A mismatch always fails.

For any other version, Opengrep's release pipeline signs every platform binary with Sigstore
(cosign keyless signing, verifiable against the public Rekor transparency
log) -- each `<asset>` ships alongside a `<asset>.sig` and `<asset>.cert`.
We download the raw signed binary directly (no archive extraction, so
there is no tar/zip-slip surface) and verify it with `cosign verify-blob`
whenever cosign is available on PATH, which is required by default: if
cosign is missing, or the release has no `.sig`/`.cert` assets, install()
refuses to proceed unless the caller explicitly passes
`require_signature=False` (`--allow-unverified` on the CLI).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

GITHUB_API = "https://api.github.com/repos/opengrep/opengrep/releases"
BINARY_NAME = "opengrep"

# The only hosts a release asset URL may resolve to. GitHub's release API
# always returns assets on one of these; anything else means the API
# response was tampered with or the endpoint itself was compromised.
# github.com answers a release download with a redirect to its asset CDN;
# release-assets.githubusercontent.com is the host it uses now (checked
# 2026-09-28), objects.githubusercontent.com the older one.
_ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
)
_DOWNLOAD_TIMEOUT_SECONDS = 60

# Opengrep's release workflow signs each binary as this GitHub Actions OIDC
# identity. Pinning both the issuer and a repo-scoped identity pattern means
# verification fails for a binary signed by any other identity, not just any
# signature that happens to validate.
_COSIGN_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
_COSIGN_IDENTITY_REGEXP = (
    r"^https://github\.com/opengrep/opengrep/\.github/workflows/.*\.yml@refs/(heads|tags)/.*$"
)


# The engine version installed by default, and the SHA-256 of each raw binary
# Rowan selects. Verified 2026-10-02: every hash equals GitHub's recorded
# asset digest, and every binary passed `sigstore verify identity` against
# Opengrep's rolling-release workflow identity (logged in Rekor). Bump the
# version and all five hashes together, re-verifying each signature.
PINNED_VERSION = "v1.29.0"
PINNED_SHA256: dict[str, str] = {
    "opengrep_osx_arm64": "dacc12a24e95b22c8b1ab55be1777b6eb877a922c5571a95b9a8de30f3963438",
    "opengrep_osx_x86": "7173bd701491b58e1d1f62c24470ca0be124ecd63885c4d6293cbf71fd706508",
    "opengrep_windows_x86.exe": "ee485b31912704dc6410bc43f04b5c6ad896697db56e360a98204abf95fa1025",
    "opengrep_manylinux_aarch64": "db3cda6e6e53251a3874e62b7c8493c281508480b3f3b4db554be41583b21174",
    "opengrep_manylinux_x86": "3365ef49d04893e01338d85d9bbd49b2bd5261ad4c9c0df0a6a0f8d44232ae13",
}


class SignatureVerificationError(RuntimeError):
    """Raised when a downloaded binary fails cosign signature verification."""


def _detect_asset_name() -> str:
    """Return the platform's raw signed-binary asset name (no archive)."""
    machine = platform.machine().lower()
    system = platform.system().lower()
    is_arm = machine in ("arm64", "aarch64")

    if system == "darwin":
        return f"opengrep_osx_{'arm64' if is_arm else 'x86'}"
    if system == "windows":
        return "opengrep_windows_x86.exe"
    # Linux: prefer manylinux for broadest glibc compatibility.
    return f"opengrep_manylinux_{'aarch64' if is_arm else 'x86'}"


def _fetch_release_info(version: str | None = None) -> dict:
    """Fetch release metadata. `version` pins a specific tag (e.g. "v1.14.0");
    omitted, this resolves whatever GitHub currently calls "latest", which
    moves without notice and picks up a yanked or backdoored release
    automatically. Prefer passing a version once you have found one you
    trust, especially in CI.
    """
    url = f"{GITHUB_API}/tags/{version}" if version else f"{GITHUB_API}/latest"
    headers = {"User-Agent": "rowan-installer"}
    # Unauthenticated API calls share a 60-per-hour limit per IP, which CI
    # runners exhaust. A token raises it; it is only sent to the API, and is
    # dropped if a redirect leaves the host.
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)  # noqa: S310
    opener = urllib.request.build_opener(_DropAuthOnHostChange())
    with opener.open(req, timeout=30) as r:
        return json.loads(r.read())


class _DropAuthOnHostChange(urllib.request.HTTPRedirectHandler):
    """urllib keeps the Authorization header across redirects; never let it
    follow one to a different host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urlparse(newurl).hostname != urlparse(req.full_url).hostname:
            new.remove_header("Authorization")
        return new


def _asset_url(release: dict, name: str) -> str | None:
    asset = next((a for a in release.get("assets", []) if a["name"] == name), None)
    return asset["browser_download_url"] if asset else None


def _check_download_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_DOWNLOAD_HOSTS:
        raise RuntimeError(
            f"Refusing to download from {url!r}: expected https:// on one of "
            f"{sorted(_ALLOWED_DOWNLOAD_HOSTS)}, got scheme={parsed.scheme!r} "
            f"host={parsed.hostname!r}. The release API response may be "
            "compromised or the endpoint mistrusted."
        )


class _AllowlistedRedirects(urllib.request.HTTPRedirectHandler):
    """Apply the download allowlist to every redirect target, not only the
    first URL (PL-16)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_download_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str, dest: Path) -> None:
    _check_download_url(url)
    opener = urllib.request.build_opener(_AllowlistedRedirects)
    with opener.open(url, timeout=_DOWNLOAD_TIMEOUT_SECONDS) as response, open(dest, "wb") as out:
        shutil.copyfileobj(response, out)


def verify_signature(binary_path: Path, sig_path: Path, cert_path: Path) -> None:
    """Verify binary_path against its Sigstore cosign signature/certificate.

    Raises SignatureVerificationError if cosign reports failure. Callers
    are responsible for deciding what to do when cosign itself is missing
    (this function assumes it's on PATH).
    """
    # List-form args, no shell=True; "cosign" is resolved via PATH lookup by
    # the OS (callers already check shutil.which("cosign") before calling
    # this), all other arguments are fixed strings or paths we downloaded.
    result = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "cosign", "verify-blob",
            "--certificate", str(cert_path),
            "--signature", str(sig_path),
            "--certificate-identity-regexp", _COSIGN_IDENTITY_REGEXP,
            "--certificate-oidc-issuer", _COSIGN_OIDC_ISSUER,
            str(binary_path),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise SignatureVerificationError(
            f"cosign signature verification FAILED for {binary_path.name}:\n"
            f"{result.stderr.strip()}\n"
            "Refusing to install a binary that fails signature verification."
        )
    print(f"Signature verified (cosign): {binary_path.name}")


def _check_pinned_sha256(dl_path: Path, asset_name: str, tag: str, expected: str) -> None:
    digest = hashlib.sha256(dl_path.read_bytes()).hexdigest()
    if digest != expected:
        # Never overridable: a wrong hash for the pinned release means the
        # download is not the binary Opengrep published.
        raise SignatureVerificationError(
            f"SHA-256 mismatch for {asset_name} {tag}: got {digest}, "
            f"expected {expected}. Refusing to install."
        )
    print(f"Verified SHA-256 against the pinned {tag} release: {asset_name}")


def _verify_with_cosign(
    release: dict, asset_name: str, tag: str, dl_path: Path, tmp: Path, require_signature: bool
) -> None:
    cosign = shutil.which("cosign")
    sig_url = _asset_url(release, f"{asset_name}.sig")
    cert_url = _asset_url(release, f"{asset_name}.cert")
    if not cosign:
        msg = (
            "cosign is not installed -- cannot verify the signature of the "
            "downloaded Opengrep binary. Install cosign "
            "(https://docs.sigstore.dev/cosign/system_config/installation/) for "
            "a verified install."
        )
        if require_signature:
            raise RuntimeError(f"{msg}\nRefusing to install unverified. Pass --allow-unverified to override.")
        print(f"WARNING: {msg}", file=sys.stderr)
    elif not (sig_url and cert_url):
        msg = f"no .sig/.cert assets found for {asset_name!r} in release {tag}"
        if require_signature:
            raise RuntimeError(f"{msg}.\nRefusing to install unverified. Pass --allow-unverified to override.")
        print(f"WARNING: {msg} -- skipping signature verification.", file=sys.stderr)
    else:
        sig_path = tmp / f"{asset_name}.sig"
        cert_path = tmp / f"{asset_name}.cert"
        _download(sig_url, sig_path)
        _download(cert_url, cert_path)
        verify_signature(dl_path, sig_path, cert_path)


def install(prefix: Path, require_signature: bool = True, version: str | None = None) -> Path:
    """Download, verify, and install the Opengrep binary.

    `version` defaults to PINNED_VERSION, which is verified against the
    built-in SHA-256 for this platform and needs no cosign; "latest" asks
    GitHub for its newest release. For any version other than the pin,
    `require_signature` (default True) makes cosign verification against
    Opengrep's own release-workflow identity mandatory: install() refuses if
    cosign is missing or the release has no signature assets. Pass
    `require_signature=False` only when you understand and accept that risk.
    """
    version = version or PINNED_VERSION
    asset_name = _detect_asset_name()
    pinned_sha256 = PINNED_SHA256.get(asset_name) if version == PINNED_VERSION else None
    if require_signature and pinned_sha256 is None and not shutil.which("cosign"):
        raise RuntimeError(
            "cosign is not installed -- cannot verify the Opengrep binary. "
            "Install cosign (https://docs.sigstore.dev/cosign/system_config/installation/) "
            "or pass --allow-unverified to override."
        )
    print(f"Fetching Opengrep release info ({version})...")
    release = _fetch_release_info(None if version == "latest" else version)
    tag = release["tag_name"]
    if pinned_sha256 is not None and tag != PINNED_VERSION:
        raise RuntimeError(f"Release API returned {tag!r}, expected {PINNED_VERSION!r}.")

    url = _asset_url(release, asset_name)
    if url is None:
        available = [a["name"] for a in release.get("assets", [])]
        raise RuntimeError(
            f"No asset matching {asset_name!r} in release {tag}.\n"
            f"Available: {available}\n"
            "Check https://github.com/opengrep/opengrep/releases"
        )
    print(f"Downloading {asset_name} ({tag}) from {url} ...")

    dest = prefix / "bin"
    dest.mkdir(parents=True, exist_ok=True)
    windows = platform.system().lower() == "windows"
    # Windows only finds executables with an extension on PATH (PL-17).
    binary_path = dest / (f"{BINARY_NAME}.exe" if windows else BINARY_NAME)

    with tempfile.TemporaryDirectory() as tmp:
        dl_path = Path(tmp) / asset_name
        _download(url, dl_path)

        if pinned_sha256 is not None:
            _check_pinned_sha256(dl_path, asset_name, tag, pinned_sha256)
        else:
            _verify_with_cosign(release, asset_name, tag, dl_path, Path(tmp), require_signature)

        shutil.copy2(dl_path, binary_path)
        # Owner-only execute: this binary is trusted and run on every scan,
        # so other local users on a shared machine should not be able to
        # execute (or, on some filesystem configurations, race-replace) it.
        if not windows:
            binary_path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    print(f"Installed: {binary_path}")
    print(f"Version: {tag}")
    if str(dest) not in os.environ.get("PATH", ""):
        print(f"\nNote: add {dest} to your PATH if it isn't already:\n  export PATH=\"{dest}:$PATH\"")
    return binary_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Install the Opengrep binary for Rowan taint analysis")
    parser.add_argument("--prefix", type=Path, default=Path.home() / ".local", help="Install prefix (binary goes to <prefix>/bin)")
    parser.add_argument("--version", default=None, help=f"Release tag (default {PINNED_VERSION}, hash-verified); other tags or 'latest' need cosign")
    parser.add_argument(
        "--allow-unverified", action="store_true",
        help="Install even if cosign or the release's signature assets are unavailable. NOT recommended.",
    )
    args = parser.parse_args()

    try:
        install(args.prefix, require_signature=not args.allow_unverified, version=args.version)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
