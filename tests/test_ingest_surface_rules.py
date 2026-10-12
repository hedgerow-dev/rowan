"""Behavioral tests for the data-ingest surface rules ns-aiml-130..134
(rules/ingest_surface.yaml).

Both mechanisms under test were reproduced by execution: fsspec's
ReferenceFileSystem rendering spec fields through an unsandboxed jinja2 on
fsspec 2026.4.0, and HDF5 external storage reading /etc/hosts through
h5py 3.16.0.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def _rule(rule_id: str):
    rules = load_neuroscan_rules(RULES_DIR / "ingest_surface.yaml")
    matches = [r for r in rules if r.metadata.id == rule_id]
    if not matches:
        pytest.fail(f"{rule_id} not found")
    return matches[0]


class TestReferenceFileSystemUse:
    """ns-aiml-130."""

    def test_direct_construction_is_flagged(self, tmp_path):
        f = tmp_path / "loader.py"
        f.write_text(
            "from fsspec.implementations.reference import ReferenceFileSystem\n"
            "\n"
            "def load(spec_path):\n"
            "    return ReferenceFileSystem(fo=spec_path, remote_protocol='s3')\n"
        )
        assert len(_rule("ns-aiml-130").check(f)) >= 1

    def test_filesystem_reference_protocol_is_flagged(self, tmp_path):
        f = tmp_path / "loader.py"
        f.write_text(
            "import fsspec\n"
            "\n"
            "def load(spec_path):\n"
            '    return fsspec.filesystem("reference", fo=spec_path)\n'
        )
        assert len(_rule("ns-aiml-130").check(f)) >= 1

    def test_reference_url_is_flagged(self, tmp_path):
        f = tmp_path / "loader.py"
        f.write_text(
            "import fsspec\n"
            "\n"
            "def load(spec_path):\n"
            '    return fsspec.open("reference://data/0", fo=spec_path)\n'
        )
        assert len(_rule("ns-aiml-130").check(f)) >= 1

    def test_ordinary_object_store_use_not_flagged(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text(
            "import fsspec\n"
            "\n"
            "def load(bucket):\n"
            '    fs = fsspec.filesystem("s3", anon=True)\n'
            '    with fsspec.open(f"s3://{bucket}/train.parquet", "rb") as fh:\n'
            "        return fh.read()\n"
        )
        assert _rule("ns-aiml-130").check(f) == []

    def test_commented_out_reference_use_not_flagged(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text(
            "import fsspec\n"
            '# legacy: fsspec.filesystem("reference", fo=spec_path)\n'
            '# also tried "reference://data/0"\n'
        )
        assert _rule("ns-aiml-130").check(f) == []


class TestFsspecPinBelowSandboxFix:
    """ns-aiml-131."""

    def test_setup_py_install_requires_pin_is_flagged(self, tmp_path):
        f = tmp_path / "setup.py"
        f.write_text(
            "from setuptools import setup\n"
            "\n"
            "setup(\n"
            "    name='loader',\n"
            "    install_requires=['fsspec==2026.4.0', 'h5py>=3.16.0'],\n"
            ")\n"
        )
        assert len(_rule("ns-aiml-131").check(f)) >= 1

    def test_older_year_pin_is_flagged(self, tmp_path):
        f = tmp_path / "setup.py"
        f.write_text("install_requires = ['fsspec==2025.9.0']\n")
        assert len(_rule("ns-aiml-131").check(f)) >= 1

    def test_dockerfile_pip_install_pin_is_flagged(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text(
            "FROM python:3.12-slim\n"
            "RUN pip install --no-cache-dir fsspec==2026.4.0 h5py==3.16.0\n"
        )
        assert len(_rule("ns-aiml-131").check(f)) >= 1

    def test_upper_bound_below_the_fix_is_flagged(self, tmp_path):
        f = tmp_path / "setup.py"
        f.write_text("install_requires = ['fsspec>=2026.1.0,<2026.6.0']\n")
        assert len(_rule("ns-aiml-131").check(f)) >= 1

    def test_conda_environment_pin_is_flagged(self, tmp_path):
        f = tmp_path / "environment.yaml"
        f.write_text("dependencies:\n  - fsspec=2026.4.0\n  - h5py=3.16.0\n")
        assert len(_rule("ns-aiml-131").check(f)) >= 1

    def test_floor_at_the_fix_not_flagged(self, tmp_path):
        f = tmp_path / "setup.py"
        f.write_text(
            "from setuptools import setup\n"
            "\n"
            "setup(\n"
            "    name='loader',\n"
            "    install_requires=['fsspec>=2026.6.0', 'h5py>=3.16.0'],\n"
            ")\n"
        )
        assert _rule("ns-aiml-131").check(f) == []

    def test_later_2026_month_not_flagged(self, tmp_path):
        """2026.10.0 is above the fix; the month regex must not read it as
        month 1."""
        f = tmp_path / "setup.py"
        f.write_text("install_requires = ['fsspec==2026.10.0']\n")
        assert _rule("ns-aiml-131").check(f) == []

    def test_other_package_with_similar_version_not_flagged(self, tmp_path):
        f = tmp_path / "setup.py"
        f.write_text("install_requires = ['s3fs==2026.4.0', 'gcsfs==2025.9.0']\n")
        assert _rule("ns-aiml-131").check(f) == []


class TestJinjaInReferenceSpec:
    """ns-aiml-132."""

    def test_gen_offset_template_is_flagged(self, tmp_path):
        f = tmp_path / "spec.json"
        f.write_text(
            "{\n"
            '  "version": 1,\n'
            '  "gen": [\n'
            "    {\n"
            '      "key": "data/{{i}}",\n'
            '      "url": "memory://blob",\n'
            '      "offset": "{{ lipsum.__globals__.os.popen(\'id\').read() }}0",\n'
            '      "length": "1"\n'
            "    }\n"
            "  ]\n"
            "}\n"
        )
        assert len(_rule("ns-aiml-132").check(f)) >= 1

    def test_refs_entry_template_is_flagged(self, tmp_path):
        f = tmp_path / "spec.json"
        f.write_text(
            "{\n"
            '  "version": 1,\n'
            '  "refs": {"data/0": ["{{ u }}payload", 0, 1]}\n'
            "}\n"
        )
        assert len(_rule("ns-aiml-132").check(f)) >= 1

    def test_templates_block_with_expression_is_flagged(self, tmp_path):
        f = tmp_path / "spec.json"
        f.write_text(
            '{"version": 1, "templates": {"u": "{{ cycler.__init__ }}"}}\n'
        )
        assert len(_rule("ns-aiml-132").check(f)) >= 1

    def test_plain_reference_spec_not_flagged(self, tmp_path):
        f = tmp_path / "spec.json"
        f.write_text(
            "{\n"
            '  "version": 1,\n'
            '  "templates": {"u": "s3://bucket/data.nc"},\n'
            '  "refs": {"data/0": ["s3://bucket/data.nc", 0, 4096]}\n'
            "}\n"
        )
        assert _rule("ns-aiml-132").check(f) == []


class TestHdf5ExternalStorage:
    """ns-aiml-133."""

    def test_create_dataset_external_is_flagged(self, tmp_path):
        f = tmp_path / "writer.py"
        f.write_text(
            "import h5py\n"
            "\n"
            "def build(container, target, n):\n"
            '    with h5py.File(container, "w") as f:\n'
            '        f.create_dataset("d", shape=(n,), dtype="u1", '
            "external=[(target, 0, n)])\n"
        )
        assert len(_rule("ns-aiml-133").check(f)) >= 1

    def test_external_link_is_flagged(self, tmp_path):
        f = tmp_path / "writer.py"
        f.write_text(
            "import h5py\n"
            "\n"
            "def link(f, other):\n"
            '    f["raw"] = h5py.ExternalLink(other, "/dataset")\n'
        )
        assert len(_rule("ns-aiml-133").check(f)) >= 1

    def test_h5pset_external_is_flagged(self, tmp_path):
        f = tmp_path / "lowlevel.py"
        f.write_text(
            "from h5py import h5p\n"
            "\n"
            "def configure(plist, name, n):\n"
            "    plist.H5Pset_external(name, 0, n)\n"
        )
        assert len(_rule("ns-aiml-133").check(f)) >= 1

    def test_ordinary_dataset_creation_not_flagged(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text(
            "import h5py\n"
            "import numpy as np\n"
            "\n"
            "def build(container):\n"
            '    with h5py.File(container, "w") as f:\n'
            '        f.create_dataset("d", data=np.zeros(16), compression="gzip")\n'
        )
        assert _rule("ns-aiml-133").check(f) == []


class TestUntrustedArtifactOpen:
    """ns-aiml-134."""

    def test_request_derived_hdf5_open_is_flagged(self, tmp_path):
        f = tmp_path / "views.py"
        f.write_text(
            "import h5py\n"
            "from flask import request\n"
            "\n"
            "def ingest():\n"
            '    with h5py.File(request.files["dataset"], "r") as f:\n'
            '        return f["d"][:100].tobytes()\n'
        )
        assert len(_rule("ns-aiml-134").check(f)) >= 1

    def test_uploaded_path_variable_is_flagged(self, tmp_path):
        f = tmp_path / "ingest.py"
        f.write_text(
            "import h5py\n"
            "\n"
            "def read_split(uploaded_path):\n"
            '    with h5py.File(uploaded_path, "r") as f:\n'
            '        return f["split"][:]\n'
        )
        assert len(_rule("ns-aiml-134").check(f)) >= 1

    def test_zarr_open_on_user_supplied_store_is_flagged(self, tmp_path):
        f = tmp_path / "ingest.py"
        f.write_text(
            "import zarr\n"
            "\n"
            "def read(user_store_url):\n"
            '    return zarr.open_group(user_store_url, mode="r")\n'
        )
        assert len(_rule("ns-aiml-134").check(f)) >= 1

    def test_kerchunk_on_uploaded_artifact_is_flagged(self, tmp_path):
        f = tmp_path / "ingest.py"
        f.write_text(
            "from kerchunk.hdf import SingleHdf5ToZarr\n"
            "\n"
            "def translate(upload_handle, url):\n"
            "    return SingleHdf5ToZarr(upload_handle, url).translate()\n"
        )
        assert len(_rule("ns-aiml-134").check(f)) >= 1

    def test_literal_trusted_path_not_flagged(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text(
            "import h5py\n"
            "\n"
            "def read_split():\n"
            '    with h5py.File("/opt/data/train.h5", "r") as f:\n'
            '        return f["split"][:]\n'
        )
        assert _rule("ns-aiml-134").check(f) == []

    def test_internal_config_path_not_flagged(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text(
            "import h5py\n"
            "\n"
            "from myapp.settings import TRAIN_SPLIT\n"
            "\n"
            "def read_split():\n"
            '    with h5py.File(TRAIN_SPLIT, "r") as f:\n'
            '        return f["split"][:]\n'
        )
        assert _rule("ns-aiml-134").check(f) == []


class TestReferenceFileSystemSanitizerRegression:
    """ns-aiml-130 must not be suppressed by an unrelated Jinja sandbox.

    The rule was originally filed under category `ssti`, which auto-applies
    `SandboxedEnvironment` as a call-shape sanitizer over a 10-line window.
    Call-shape sanitizers suppress unconditionally, so a codebase that
    correctly sandboxes its own templating within 10 lines of a
    ReferenceFileSystem call silently lost the finding. That sandbox is
    irrelevant to this bug: the unsafe render happens inside fsspec itself.
    """

    def test_unrelated_sandboxed_environment_does_not_suppress(self, tmp_path):
        f = tmp_path / "loader.py"
        f.write_text(
            "import fsspec\n"
            "from jinja2.sandbox import SandboxedEnvironment\n"
            "\n"
            "env = SandboxedEnvironment()\n"
            "\n"
            "def render_report(tpl, ctx):\n"
            "    return env.from_string(tpl).render(**ctx)\n"
            "\n"
            "def load_dataset(spec_path):\n"
            '    fs = fsspec.filesystem("reference", fo=spec_path)\n'
            '    return fs.open("data/0").read()\n'
        )
        assert len(_rule("ns-aiml-130").check(f)) >= 1

    def test_unrelated_render_template_does_not_suppress(self, tmp_path):
        f = tmp_path / "views.py"
        f.write_text(
            "import fsspec\n"
            "from flask import render_template\n"
            "\n"
            "def index():\n"
            '    return render_template("index.html")\n'
            "\n"
            "def load_dataset(spec_path):\n"
            '    fs = fsspec.filesystem("reference", fo=spec_path)\n'
            '    return fs.open("data/0").read()\n'
        )
        assert len(_rule("ns-aiml-130").check(f)) >= 1


class TestKerchunkVersusTemplatedJson:
    """ns-aiml-132 must not fire on ordinary templated JSON (#53)."""

    def test_postman_collection_not_flagged(self, tmp_path):
        f = tmp_path / "collection.json"
        f.write_text(
            "{\n"
            '  "request": {"url": "{{base_url}}/v1/users", "header": [{"key": "{{token}}"}]}\n'
            "}\n"
        )
        assert _rule("ns-aiml-132").check(f) == []
