"""Cloud and CORS regex rules that matched the wrong thing (#53).

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


def _fires(tmp_path, rule_file, rule_id, filename, src):
    (tmp_path / filename).write_text(src, encoding="utf-8")
    return any(f.rule_id == rule_id for f in OpengrepAdapter().scan_with_rules(tmp_path, [CONVERTED / rule_file]))


FIRES = [
    ("cloud_rules.yaml", "ns-cloud-001", "s3.py", "s3.put_object(Bucket='b', Key='k', ACL='public-read')\n"),
    ("cloud_rules.yaml", "ns-cloud-001", "stack.ts", "new s3.Bucket(this, 'B', { publicReadAccess: true });\n"),
    ("cloud_rules.yaml", "ns-cloud-001", "S3.java", "req.withCannedAcl(CannedAccessControlList.PublicRead);\n"),
    ("cloud_rules.yaml", "ns-cloud-001", "s3.go", "in := &s3.PutBucketAclInput{ACL: s3.BucketCannedACLPublicReadWrite}\n"),
    ("cloud_rules.yaml", "ns-cloud-002", "policy.py", 'policy = {"Effect": "Allow", "Action": "*"}\n'),
    ("cloud_rules.yaml", "ns-cloud-002", "policy.py", 'policy = {"Effect": "Allow", "Action": ["*"]}\n'),
    ("cloud_rules.yaml", "ns-cloud-002", "policy.py", 'policy = {"Effect": "Allow", "Action": "s3:*"}\n'),
    ("security_surface.yaml", "NS-CACHE-001", "app.js", "app.use(cors({ origin: '*' }));\n"),
    ("security_surface.yaml", "NS-CACHE-001", "app.js", "app.use(cors({ origin: true, credentials: true }));\n"),
]

QUIET = [
    ("cloud_rules.yaml", "ns-cloud-001", "s3.py", "s3.put_bucket_acl(Bucket='public-assets', ACL='private')\n"),
    ("cloud_rules.yaml", "ns-cloud-002", "policy.py",
     'stmt = {"Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*"}\n'),
    ("cloud_rules.yaml", "ns-cloud-002", "policy.py", "iam.put_role_policy(RoleName=r, PolicyName='p*', PolicyDocument=d)\n"),
]


@pytest.mark.parametrize("rule_file,rule_id,filename,src", FIRES)
def test_fires(tmp_path, rule_file, rule_id, filename, src):
    assert _fires(tmp_path, rule_file, rule_id, filename, src), src


@pytest.mark.parametrize("rule_file,rule_id,filename,src", QUIET)
def test_quiet(tmp_path, rule_file, rule_id, filename, src):
    assert not _fires(tmp_path, rule_file, rule_id, filename, src), src


def test_express_cors_duplicate_is_removed():
    text = (Path(__file__).parent.parent / "rules" / "framework_rules.yaml").read_text(encoding="utf-8")
    assert "id: ns-fw-js-002\n" not in text
