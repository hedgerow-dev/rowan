"""LF-5 tenant and ownership authorization regressions."""

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.authz import AuthzPass
from rowan.passes.base import ScanContext
from rowan.pipeline import ScanPipeline


def _scan(tmp_path, source: str, rule_id: str):
    (tmp_path / "api.py").write_text(source, encoding="utf-8")
    ctx = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path, enable_authz=True),
        result=ScanResult(),
    )
    return [f for f in AuthzPass().run(ctx).findings if f.rule_id == rule_id]


def _scan_files(tmp_path, files: dict[str, str], rule_id: str):
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    ctx = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path, enable_authz=True),
        result=ScanResult(),
    )
    return [f for f in AuthzPass().run(ctx).findings if f.rule_id == rule_id]


def test_caller_can_override_principal_despite_current_user_default(tmp_path):
    source = (
        "@bp.get('/count')\n"
        "@require_auth\n"
        "def count():\n"
        "    total = count_by_owner(request.args.get('owner', str(g.user_id)))\n"
        "    return jsonify(count=total)\n"
    )
    hits = _scan(tmp_path, source, "AUTHZ-PRINCIPAL-OVERRIDE-001")
    assert len(hits) == 1
    assert hits[0].start_line == 4
    assert hits[0].metadata["principal_parameter"] == "owner"


def test_principal_override_rejected_before_use_is_safe(tmp_path):
    source = (
        "@bp.get('/count')\n"
        "@require_auth\n"
        "def count():\n"
        "    owner = request.args.get('owner_id', str(g.user_id))\n"
        "    if owner != str(g.user_id):\n"
        "        abort(403)\n"
        "    return jsonify(count=count_by_owner(owner))\n"
    )
    assert _scan(tmp_path, source, "AUTHZ-PRINCIPAL-OVERRIDE-001") == []


def test_principal_override_partial_non_privilege_guard_is_not_safe(tmp_path):
    source = (
        "@bp.get('/count')\n"
        "@require_auth\n"
        "def count():\n"
        "    owner = request.args.get('owner_id', str(g.user_id))\n"
        "    if owner != str(g.user_id) and debug_mode:\n"
        "        abort(403)\n"
        "    return jsonify(count=count_by_owner(owner))\n"
    )
    assert len(_scan(tmp_path, source, "AUTHZ-PRINCIPAL-OVERRIDE-001")) == 1


def test_server_selected_principal_is_safe(tmp_path):
    source = (
        "@bp.get('/count')\n"
        "@require_auth\n"
        "def count():\n"
        "    return jsonify(count=count_by_owner(g.user_id))\n"
    )
    assert _scan(tmp_path, source, "AUTHZ-PRINCIPAL-OVERRIDE-001") == []


def test_non_principal_query_default_is_not_an_owner_override(tmp_path):
    source = (
        "@bp.get('/search')\n"
        "@require_auth\n"
        "def search():\n"
        "    page = request.args.get('page', str(g.user_id))\n"
        "    return list_page(page)\n"
    )
    assert _scan(tmp_path, source, "AUTHZ-PRINCIPAL-OVERRIDE-001") == []


def test_authenticated_search_reaches_unscoped_raw_sql_helper(tmp_path):
    files = {
        "api.py": (
            "from services.experiments import search_by_tag\n\n"
            "@bp.get('/by_tag')\n"
            "@require_auth\n"
            "def by_tag():\n"
            "    return jsonify(search_by_tag(request.args.get('tag', '')))\n"
        ),
        "services/experiments.py": (
            "def search_by_tag(tag):\n"
            "    query = text(\n"
            "        'SELECT id, name, owner_id, tags FROM experiments '\n"
            "        'WHERE tags = :tag ORDER BY id DESC'\n"
            "    )\n"
            "    return db.session.execute(query, {'tag': tag}).mappings().all()\n"
        ),
    }
    hits = _scan_files(tmp_path, files, "AUTHZ-TENANT-SCOPE-001")
    assert len(hits) == 1
    assert hits[0].start_line == 6
    assert hits[0].metadata["helper"] == "search_by_tag"
    assert hits[0].metadata["model"] == "experiments"


def test_owner_scoped_raw_sql_helper_is_safe(tmp_path):
    files = {
        "api.py": (
            "from services.experiments import search_by_tag\n\n"
            "@bp.get('/by_tag')\n"
            "@require_auth\n"
            "def by_tag():\n"
            "    return jsonify(search_by_tag(request.args.get('tag', ''), g.user_id))\n"
        ),
        "services/experiments.py": (
            "def search_by_tag(tag, owner_id):\n"
            "    query = text(\n"
            "        'SELECT id, name, owner_id, tags FROM experiments '\n"
            "        'WHERE tags = :tag AND owner_id = :owner'\n"
            "    )\n"
            "    return db.session.execute(\n"
            "        query, {'tag': tag, 'owner': owner_id}\n"
            "    ).mappings().all()\n"
        ),
    }
    assert _scan_files(tmp_path, files, "AUTHZ-TENANT-SCOPE-001") == []


def test_direct_unscoped_orm_collection_query_is_flagged(tmp_path):
    source = (
        "def seed(current_user):\n"
        "    return Model(owner_id=current_user.id)\n"
        "\n"
        "@bp.get('/models')\n"
        "@require_auth\n"
        "def list_models():\n"
        "    rows = Model.query.filter_by(status='ready').all()\n"
        "    return jsonify(rows)\n"
    )
    hits = _scan(tmp_path, source, "AUTHZ-TENANT-SCOPE-001")
    assert len(hits) == 1
    assert hits[0].metadata["model"] == "Model"


def test_direct_owner_scoped_orm_collection_query_is_safe(tmp_path):
    source = (
        "@bp.get('/models')\n"
        "@require_auth\n"
        "def list_models():\n"
        "    rows = Model.query.filter_by(owner_id=g.user_id).all()\n"
        "    return jsonify(rows)\n"
    )
    assert _scan(tmp_path, source, "AUTHZ-TENANT-SCOPE-001") == []


def test_owner_scoped_write_then_unscoped_rag_retrieval_is_flagged(tmp_path):
    source = (
        "@bp.post('/notes')\n"
        "@require_auth\n"
        "def add_note():\n"
        "    row = ExperimentNote(owner_id=g.user_id, note=request.json['note'])\n"
        "    db.session.add(row)\n\n"
        "@bp.post('/brief')\n"
        "@require_auth\n"
        "def brief():\n"
        "    rows = ExperimentNote.query.filter_by(experiment_id=request.json['id']).all()\n"
        "    docs = [row.note for row in rows]\n"
        "    return run_agent('summarize', context_docs=docs)\n"
    )
    hits = _scan(tmp_path, source, "AUTHZ-RAG-TENANT-SCOPE-001")
    assert len(hits) == 1
    assert hits[0].start_line == 12
    assert hits[0].metadata["model"] == "ExperimentNote"


def test_owner_scoped_rag_retrieval_is_safe(tmp_path):
    source = (
        "@bp.post('/notes')\n"
        "@require_auth\n"
        "def add_note():\n"
        "    db.session.add(ExperimentNote(owner_id=g.user_id, note='private'))\n\n"
        "@bp.post('/brief')\n"
        "@require_auth\n"
        "def brief():\n"
        "    rows = ExperimentNote.query.filter_by(owner_id=g.user_id).all()\n"
        "    docs = [row.note for row in rows]\n"
        "    return run_agent('summarize', context_docs=docs)\n"
    )
    assert _scan(tmp_path, source, "AUTHZ-RAG-TENANT-SCOPE-001") == []


def test_deep_policy_runs_authz(tmp_path):
    """--policy deep selects the pass with enable_authz left at None."""
    (tmp_path / "api.py").write_text(
        "@bp.post('/notes')\n"
        "@require_auth\n"
        "def add_note():\n"
        "    row = ExperimentNote(owner_id=g.user_id, note=request.json['note'])\n"
        "    db.session.add(row)\n\n"
        "@bp.post('/brief')\n"
        "@require_auth\n"
        "def brief():\n"
        "    rows = ExperimentNote.query.filter_by(experiment_id=request.json['id']).all()\n"
        "    docs = [row.note for row in rows]\n"
        "    return run_agent('summarize', context_docs=docs)\n",
        encoding="utf-8",
    )
    result = ScanPipeline(ScanConfig(target=tmp_path, policy="deep", enable_sca=False)).run()
    assert "AUTHZ-RAG-TENANT-SCOPE-001" in {f.rule_id for f in result.findings}


def test_unscoped_rag_retrieval_after_unrelated_unscoped_query_is_flagged(tmp_path):
    """An earlier unscoped query on a non-owner model must not hide the owner-model one."""
    source = (
        "@bp.post('/notes')\n"
        "@require_auth\n"
        "def add_note():\n"
        "    row = ExperimentNote(owner_id=g.user_id, note=request.json['note'])\n"
        "    db.session.add(row)\n\n"
        "@bp.post('/brief')\n"
        "@require_auth\n"
        "def brief():\n"
        "    tags = Tag.query.filter_by(kind='public').all()\n"
        "    rows = ExperimentNote.query.filter_by(experiment_id=request.json['id']).all()\n"
        "    docs = [row.note for row in rows]\n"
        "    return run_agent('summarize', context_docs=docs)\n"
    )
    hits = _scan(tmp_path, source, "AUTHZ-RAG-TENANT-SCOPE-001")
    assert len(hits) == 1
    assert hits[0].metadata["model"] == "ExperimentNote"

