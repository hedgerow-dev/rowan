"""SCA must only read regular, in-repo dependency files.

Companion files (a lockfile's pyproject.toml/package.json, gradle.properties
up the tree) used to be opened with no check at all: a FIFO hung the scan,
and a gradle.properties symlink out of the repo resolved ``$signingPassword``
into a version that was printed in the report and sent to osv.dev.
"""

from __future__ import annotations

import os
import signal
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from rowan.passes.sca import SCAPass

SECRET = "S3CRET-hunter2"


class _Hung(BaseException):
    """Not an OSError, so SCA's own error handling cannot swallow it."""


@contextmanager
def _deadline(seconds: int):
    def expire(signum, frame):
        raise _Hung("SCA read did not return")

    previous = signal.signal(signal.SIGALRM, expire)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _run(root):
    """Run the pass with OSV mocked out; return (result, queried packages)."""
    queried: list[dict] = []

    def fake_query(packages):
        queried.extend(packages)
        return [{} for _ in packages]

    sca = SCAPass()
    with (
        patch.object(sca, "_query_osv_batch", side_effect=fake_query),
        patch.object(sca, "_apply_epss"),
    ):
        result = sca.run(MagicMock(target_path=root))
    return result, queried


def test_gradle_properties_symlink_out_of_repo_is_not_read(tmp_path):
    outside = tmp_path / "home"
    outside.mkdir()
    (outside / "gradle.properties").write_text(f"signingPassword={SECRET}\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "build.gradle").write_text(
        'dependencies {\n  implementation "org.apache.logging.log4j:log4j-core:$signingPassword"\n}\n'
    )
    (repo / "gradle.properties").symlink_to(outside / "gradle.properties")

    result, queried = _run(repo)

    assert SECRET not in repr(queried)
    assert SECRET not in repr(result.metadata)
    assert SECRET not in repr(result.degraded_passes)
    assert "gradle.properties" in result.degraded_passes["sca"]


def test_non_version_property_is_never_interpolated(tmp_path):
    (tmp_path / "gradle.properties").write_text(
        f"signingPassword={SECRET}\nlogback_version=1.5.21\n"
    )
    (tmp_path / "build.gradle").write_text(
        "dependencies {\n"
        '  implementation "org.example:leak:$signingPassword"\n'
        '  implementation "ch.qos.logback:logback-classic:${logback_version}"\n'
        "}\n"
    )

    result, queried = _run(tmp_path)

    assert SECRET not in repr(queried)
    assert SECRET not in repr(result.metadata)
    versions = {p["name"]: p["version"] for p in queried}
    assert versions == {"org.example:leak": "*", "ch.qos.logback:logback-classic": "1.5.21"}


def test_pom_non_version_property_stays_literal(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text(
        "<project><properties>"
        f"<secret.value>{SECRET}</secret.value><spring.version>5.3.20.RELEASE</spring.version>"
        "</properties><dependencies>"
        "<dependency><groupId>a</groupId><artifactId>b</artifactId><version>${secret.value}</version></dependency>"
        "<dependency><groupId>c</groupId><artifactId>d</artifactId><version>${spring.version}</version></dependency>"
        "</dependencies></project>"
    )
    versions = {p["name"]: p["version"] for p in SCAPass()._extract_packages(pom)}
    assert versions == {"a:b": "${secret.value}", "c:d": "5.3.20.RELEASE"}


def test_fifo_companion_does_not_hang_the_scan(tmp_path):
    (tmp_path / "Pipfile.lock").write_text('{"default": {"requests": {"version": "==2.31.0"}}}')
    os.mkfifo(tmp_path / "pyproject.toml")

    with _deadline(5):
        result, queried = _run(tmp_path)

    assert [p["name"] for p in queried] == ["requests"]
    assert "pyproject.toml" in result.degraded_passes["sca"]


def test_fifo_python_file_does_not_hang_reachability(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    os.mkfifo(tmp_path / "a.py")

    with _deadline(5):
        _, queried = _run(tmp_path)

    assert [p["name"] for p in queried] == ["requests"]


def test_device_symlink_inside_repo_is_not_read(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        '{"dependencies": {"lodash": {"version": "4.17.20"}}}'
    )
    (tmp_path / "package.json").symlink_to("/dev/zero")

    with _deadline(5):
        result, queried = _run(tmp_path)

    assert [p["name"] for p in queried] == ["lodash"]
    assert "package.json" in result.degraded_passes["sca"]


def test_in_repo_symlink_to_regular_file_is_skipped(tmp_path):
    (tmp_path / "real.txt").write_text("django==3.2.0\n")
    link = tmp_path / "requirements.txt"
    link.symlink_to(tmp_path / "real.txt")
    sca = SCAPass()
    sca._scan_root = tmp_path
    assert sca._read_text(link) is None
    assert str(link) in sca._skipped_files


def test_missing_companion_is_silent(tmp_path):
    (tmp_path / "requirements.txt").write_text("django==3.2.0\n")
    result, queried = _run(tmp_path)
    assert [p["name"] for p in queried] == ["django"]
    assert "sca" not in result.degraded_passes


@pytest.mark.parametrize(
    "version", ["1.2.3", "2.0.0-RC1", "5.3.20.RELEASE", "1.0.0.Final", "33.0.0-jre", "7"]
)
def test_plain_versions_still_resolve(version):
    assert SCAPass._is_plain_version(version)


@pytest.mark.parametrize(
    "value", [SECRET, "hunter2", "abc", "9fK2xq", "1.2.3 secret", "https://x/y", "1" * 80]
)
def test_non_versions_are_rejected(value):
    assert not SCAPass._is_plain_version(value)
