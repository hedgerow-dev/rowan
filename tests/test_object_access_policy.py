"""Policy declarations refine guard gaps, not unknown runtime behavior."""

import json

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult, Severity
from rowan.passes.authz import AuthzPass
from rowan.passes.base import ScanContext
from rowan.passes.enrichment import EnrichmentPass
from rowan.pipeline import ScanPipeline
from rowan.project_config import ProjectConfigError, apply_project_config, load_project_config
from rowan.reporters import to_json


def scan(tmp_path, body, policies=None, model_import="from models import Parcel"):
    (tmp_path / "models.py").write_text("class Parcel:\n    pass\n")
    (tmp_path / "app.py").write_text(
        model_import
        + '\n@app.get("/parcel/{key}")\ndef handler(key):\n    row = Parcel.query.get(key)\n'
        + "".join("    " + s + "\n" for s in body.splitlines())
    )
    (tmp_path / "principal.py").write_text("def principal():\n    return current_user.id\n")
    config = ScanConfig(target=tmp_path, enable_authz=True, authz_model_policies=policies or {})
    ctx = ScanContext(target_path=tmp_path, config=config, result=ScanResult())
    findings = [f for f in AuthzPass().run(ctx).findings if f.rule_id == "AUTHZ-BOLA-001"]
    EnrichmentPass()._cap_unverified_severity(findings)
    return findings


def test_unknown_policy_keeps_gap_but_not_confirmed_impact(tmp_path):
    found = scan(tmp_path, 'return {"label": row.label}')
    assert len(found) == 1 and found[0].severity == Severity.MEDIUM
    assert found[0].metadata["authorization_requirement"] == "unverified"
    assert found[0].metadata["object_use"] == "read"
    assert found[0].metadata["model_identity"] == "models.Parcel"
    pipeline = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True))
    assert pipeline._in_actionable_view(found[0])
    assert not pipeline._in_confirmed_view(found[0])
    assert (
        json.loads(to_json(ScanResult(findings=found)))["findings"][0]["evidence_tier"]
        == "authorization-gap"
    )


@pytest.mark.parametrize(
    "body",
    [
        "return row is not None",
        'if not row:\n    return {"error": "missing"}\nreturn {"exists": True}',
    ],
)
def test_existence_is_distinct_from_content_disclosure(tmp_path, body):
    found = scan(tmp_path, body)
    assert len(found) == 1 and found[0].severity == Severity.LOW
    assert found[0].metadata["object_use"] == "existence"


def test_explicit_public_read_can_remove_a_read_only_gap(tmp_path):
    assert not scan(tmp_path, 'return {"label": row.label}', {"models.Parcel": {"read": "public"}})


@pytest.mark.parametrize(
    "body",
    [
        'row.label = request.json["label"]\nreturn {"label": row.label}',
        'db.session.delete(row)\nreturn {"status": "gone"}',
        'row.promote()\nreturn {"label": row.label}',
        'custom(row)\nreturn {"label": row.label}',
        'alias = row\nalias.label = value\nreturn {"status": "done"}',
    ],
)
def test_public_reads_never_allow_writes_or_unresolved_whole_object_calls(tmp_path, body):
    found = scan(tmp_path, body, {"models.Parcel": {"read": "public"}})
    assert len(found) == 1
    assert found[0].metadata["object_use"] in {"write", "unknown"}
    assert found[0].metadata["authorization_requirement"] == "unverified"


def test_declared_principal_requirement_retains_strong_missing_guard(tmp_path):
    found = scan(tmp_path, 'return {"label": row.label}', {"models.Parcel": {"read": "principal"}})
    assert found[0].severity == Severity.HIGH
    assert found[0].metadata["authorization_requirement"] == "principal"


def test_public_policy_does_not_match_an_unresolved_model_import(tmp_path):
    found = scan(
        tmp_path,
        'return {"label": row.label}',
        {"models.Parcel": {"read": "public"}},
        "from external import Parcel",
    )
    assert len(found) == 1 and found[0].metadata["model_identity"] is None


@pytest.mark.parametrize(
    "policy",
    [
        {"Parcel": {"read": "public"}},
        {"models.Parcel": {"write": "public"}},
        {"models.Parcel": {"read": "private"}},
        {"models.Parcel": {"read": {}}},
        ["models.Parcel"],
    ],
)
def test_invalid_policy_is_rejected(tmp_path, policy):
    with pytest.raises(ValueError):
        ScanConfig(target=tmp_path, authz_model_policies=policy)


def test_project_config_policy_and_ci_opt_in(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from rowan import cli

    cfg = tmp_path / ".rowan.yml"
    cfg.write_text(
        "authz_model_policies:\n  models.Parcel:\n    read: public\n    write: principal\n"
    )
    config = ScanConfig(target=tmp_path)
    apply_project_config(load_project_config(cfg), cfg, config)
    assert config.authz_model_policies == {
        "models.Parcel": {"read": "public", "write": "principal"}
    }
    captured = []

    class FakePipeline:
        def __init__(self, config):
            captured.append(config)

        def run(self):
            return ScanResult()

    monkeypatch.setattr(cli, "ScanPipeline", FakePipeline)
    runner = CliRunner()
    assert runner.invoke(cli.main, ["scan", str(tmp_path), "--ci"]).exit_code == 0
    assert captured[-1].authz_model_policies == {}
    assert (
        runner.invoke(cli.main, ["scan", str(tmp_path), "--ci", "--project-config"]).exit_code == 0
    )
    assert captured[-1].authz_model_policies == config.authz_model_policies
    cfg.write_text("authz_model_policies:\n  models.Parcel:\n    write: public\n")
    with pytest.raises(ProjectConfigError):
        load_project_config(cfg)


def test_rebound_model_export_does_not_inherit_public_policy(tmp_path):
    scan(tmp_path, 'return {"label": row.label}')
    (tmp_path / "models.py").write_text("class Parcel:\n    pass\nParcel = PrivateObject\n")
    config = ScanConfig(
        target=tmp_path,
        enable_authz=True,
        authz_model_policies={"models.Parcel": {"read": "public"}},
    )
    ctx = ScanContext(target_path=tmp_path, config=config, result=ScanResult())
    found = [f for f in AuthzPass().run(ctx).findings if f.rule_id == "AUTHZ-BOLA-001"]
    assert len(found) == 1 and found[0].metadata["model_identity"] is None


@pytest.mark.parametrize(
    "action",
    [
        "queue_action(key)",
        'payload = {"selected": key}\nqueue_action(payload)',
    ],
)
def test_existence_check_does_not_authorize_a_deferred_selector_operation(tmp_path, action):
    body = (
        'if not row:\n    return {"error": "missing"}\n' + action + '\nreturn {"status": "queued"}'
    )
    found = scan(tmp_path, body, {"models.Parcel": {"read": "public"}})
    assert len(found) == 1
    assert found[0].metadata["object_use"] == "unknown"
    assert found[0].severity == Severity.MEDIUM


@pytest.mark.parametrize(
    "action",
    [
        'custom({"row": row})',
        "custom(callback=row.promote)",
        "custom(row.label)",
    ],
)
def test_nested_object_and_bound_method_escapes_remain_unknown(tmp_path, action):
    found = scan(
        tmp_path, action + '\nreturn {"label": row.label}', {"models.Parcel": {"read": "public"}}
    )
    assert len(found) == 1 and found[0].metadata["object_use"] == "unknown"


def test_same_line_object_escape_is_not_mistaken_for_public_read(tmp_path):
    (tmp_path / "models.py").write_text("class Parcel:\n    pass\n")
    (tmp_path / "app.py").write_text(
        'from models import Parcel\n@app.get("/parcel/{key}")\ndef handler(key):\n    row = Parcel.query.get(key); custom(row)\n    return row.label\n'
    )
    (tmp_path / "principal.py").write_text("def principal():\n    return current_user.id")
    config = ScanConfig(
        target=tmp_path,
        enable_authz=True,
        authz_model_policies={"models.Parcel": {"read": "public"}},
    )
    ctx = ScanContext(target_path=tmp_path, config=config, result=ScanResult())
    found = [f for f in AuthzPass().run(ctx).findings if f.rule_id == "AUTHZ-BOLA-001"]
    assert len(found) == 1 and found[0].metadata["object_use"] == "unknown"


def test_unused_lookup_with_deferred_selector_action_is_not_low(tmp_path):
    found = scan(
        tmp_path,
        'queue_action(key)\nreturn {"status": "queued"}',
        {"models.Parcel": {"read": "public"}},
    )
    assert len(found) == 1 and found[0].severity == Severity.MEDIUM
    assert found[0].metadata["object_use"] == "unknown"


def test_a_trace_does_not_prove_access_policy(tmp_path):
    from rowan.core.findings import TaintFlow, TaintNode

    found = scan(tmp_path, 'return {"label": row.label}')
    found[0].taint_flow = TaintFlow(source=TaintNode("app.py", 3, snippet='request.args["key"]'))
    EnrichmentPass()._cap_unverified_severity(found)
    assert found[0].metadata["evidence_tier"] == "authorization-gap"
    pipeline = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True))
    assert not pipeline._in_confirmed_view(found[0])
