"""Heuristic regex rules that matched ordinary code, or missed common forms (#53).

Runs the converted rules, the default engine. Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

CONVERTED = Path(__file__).parent.parent / "rules" / "converted"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _fires(tmp_path, rule_file, rule_id, src):
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [CONVERTED / rule_file], languages=["python"])
    return any(f.rule_id == rule_id for f in findings)


FIRES = [
    ("python_web_surface.yaml", "ns-websec-598-001", "token = request.query_params.get('token')\n"),
    ("python_web_surface.yaml", "ns-websec-598-001", "key = request.values.get('api_key')\n"),
    ("python_web_surface.yaml", "ns-websec-598-001", "token = request.args.get('token')\n"),
    ("python_web_surface.yaml", "ns-websec-276-001", "import os\nos.chmod(os.path.join(d, 'x'), 0o777)\n"),
    ("python_web_surface.yaml", "ns-websec-276-001", "from pathlib import Path\nPath(p).chmod(0o777)\n"),
    ("python_web_surface.yaml", "ns-websec-276-001", "import os\nos.chmod(p, 0o666)\n"),
    ("inference_plane.yaml", "ns-aiml-140", "class Req(BaseModel):\n    remote_engine_id: str = Field(None)\n"),
    ("inference_plane.yaml", "ns-aiml-142", "key = int(hex_part, 16) & 0xFFFF  # cache_key\n"),
    ("inference_plane.yaml", "ns-aiml-142", "block_key = hashlib.sha256(b).hexdigest()[:8]\n"),
    ("inference_plane.yaml", "ns-aiml-143", "h = hash(tuple(token_ids))\n"),
    ("ingest_surface.yaml", "ns-aiml-134", "import h5py\nf = h5py.File(request.files['f'], 'r')\n"),
]

QUIET = [
    ("python_web_surface.yaml", "ns-websec-276-001", "import os\nos.chmod(p, 0o1777)\n"),
    ("python_web_surface.yaml", "ns-websec-276-001", "import os\nos.chmod(p, 0o755)\n"),
    ("inference_plane.yaml", "ns-aiml-140",
     "class Tunnel(BaseModel):\n    remote_host: str = Field(...)\n    remote_port: int = Field(...)\n"),
    ("inference_plane.yaml", "ns-aiml-140", "class Req(BaseModel):\n    cache_salt: str = Field(None)\n"),
    ("inference_plane.yaml", "ns-aiml-142", "b = (hash_value >> 8) & 0xFF\n"),
    ("inference_plane.yaml", "ns-aiml-142", "h = digest[0] & 0xff\n"),
    ("inference_plane.yaml", "ns-aiml-142", "block_key = hashlib.sha256(b).hexdigest()[:16]\n"),
    ("inference_plane.yaml", "ns-aiml-142", "tokenizer_hash = hashlib.md5(b).hexdigest()[:8]\n"),
    ("inference_plane.yaml", "ns-aiml-143", "import os\nos.environ['PYTHONHASHSEED'] = str(seed)\n"),
    ("ingest_surface.yaml", "ns-aiml-134", "import h5py\nf = h5py.File(self.filename, 'r')\n"),
    ("ingest_surface.yaml", "ns-aiml-134", "import h5py\nf = h5py.File(user_dir / 'a.h5')\n"),
    ("ingest_surface.yaml", "ns-aiml-134", "import h5py\nf = h5py.File(remote_cache_path)\n"),
]


@pytest.mark.parametrize("rule_file,rule_id,src", FIRES)
def test_fires(tmp_path, rule_file, rule_id, src):
    assert _fires(tmp_path, rule_file, rule_id, src), src


@pytest.mark.parametrize("rule_file,rule_id,src", QUIET)
def test_quiet(tmp_path, rule_file, rule_id, src):
    assert not _fires(tmp_path, rule_file, rule_id, src), src
