"""Regex rules that reported the wrong thing (#53). Runs the converted rules,
the default engine. Requires the Opengrep binary.
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


def _fires(tmp_path, rule_file, rule_id, filename, src):
    (tmp_path / filename).write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [CONVERTED / rule_file])
    return any(f.rule_id == rule_id for f in findings)


FIRES = [
    ("templates.yaml", "NS-TPL-002", "t.html", "<div>{{ bio|safe }}</div>\n"),
    ("templates.yaml", "NS-TPL-002", "t.html", "<div>{{ x|safe -}}</div>\n"),
    ("templates.yaml", "NS-TPL-002", "t.html", "<div>{{ f({'a': 1})|safe }}</div>\n"),
    ("misc_rules.yaml", "ns-bb-014", "s.py", "import random\nsalt = random.getrandbits(64)\n"),
    ("misc_rules.yaml", "ns-bb-014", "s.py", "import random\nkey = bytes(random.getrandbits(8) for _ in range(32))\n"),
    ("cloud_rules.yaml", "ns-cloud-004", "db.py", "authorized_networks = ['0.0.0.0/0']\n"),
    ("cloud_rules.yaml", "ns-cloud-004", "db.ts", "new rds.DatabaseInstance(this, 'Db', { publiclyAccessible: true });\n"),
    ("cloud_rules.yaml", "ns-cloud-005", "trail.py", "cloudtrail.put_trail_status(IsLogging=false)\n"),
    ("cloud_rules.yaml", "ns-cloud-007", "sg.py", "rule = {'IpProtocol': '-1', 'CidrIp': '10.0.0.0/16'}\n"),
    ("cloud_rules.yaml", "ns-cloud-007", "sg.py", "sg_rule(from_port=0, to_port=65535)\n"),
]

QUIET = [
    ("templates.yaml", "NS-TPL-002", "t.html", "<script>var d = {{ data|tojson|safe }};</script>\n"),
    ("misc_rules.yaml", "ns-bb-014", "ml.py", "import random\ntoken_ids = random.sample(range(vocab), k)\n"),
    ("misc_rules.yaml", "ns-bb-014", "ml.py", "import random\nmax_tokens = random.randint(10, 50)\n"),
    ("misc_rules.yaml", "ns-bb-014", "ml.py", "import random\ntokens = random.choices(vocab, k=10)\n"),
    ("cloud_rules.yaml", "ns-cloud-003", "s3.py", "def create(self, kms_key_id=None):\n    pass\n"),
    ("cloud_rules.yaml", "ns-cloud-004", "db.py", "authorized_networks = ['10.0.0.0/8']\n"),
    ("cloud_rules.yaml", "ns-cloud-005", "db.js", "const sequelize = new Sequelize(url, { logging: false });\n"),
    ("cloud_rules.yaml", "ns-cloud-007", "sg.py",
     "rule = {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'region': 'us-east-1'}\n"),
    ("cloud_rules.yaml", "ns-cloud-007", "sg.py", "sg_rule(from_port=1024, to_port=65535)\n"),
]


@pytest.mark.parametrize("rule_file,rule_id,filename,src", FIRES)
def test_fires(tmp_path, rule_file, rule_id, filename, src):
    assert _fires(tmp_path, rule_file, rule_id, filename, src), src


@pytest.mark.parametrize("rule_file,rule_id,filename,src", QUIET)
def test_quiet(tmp_path, rule_file, rule_id, filename, src):
    assert not _fires(tmp_path, rule_file, rule_id, filename, src), src


def test_removed_rules_are_gone():
    text = "".join(p.read_text(encoding="utf-8") for p in CONVERTED.glob("*.yaml"))
    assert "NS-TPL-003" not in text
    assert "ns-websec-330-001" not in text
