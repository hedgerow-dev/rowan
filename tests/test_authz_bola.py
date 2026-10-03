"""Object-level authorization (BOLA/IDOR) detection tests -- AuthzPass.

Phase 1 (issue #171) covers the ownership model in its query-fused form only,
High-confidence-only, gated on the repo having a principal concept. Phase 2
(issue #172) adds the fetch-then-guard shape via `collect_dominating_candidates`.
Phase 3 (issue #173) completes the four-model taxonomy (membership,
hierarchical, status) plus function/class-level decorator gates. See ADR-0003.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import Category, ScanResult, Severity
from rowan.passes.authz import AuthzPass
from rowan.passes.base import ScanContext

# A benign reference to the principal, so the repo demonstrably has a "current
# user" concept -- the precondition for calling a missing ownership check a BOLA.
_PRINCIPAL_FILE = (
    "def whoami(request):\n"
    "    return request.user.id\n"
)


def _make_project(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="rowan_authz_"))
    for name, content in files.items():
        if name.endswith("views.py") and "django" not in content and "rest_framework" not in content:
            content = "from django.http import HttpResponse\n" + content
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def _run(root: Path, *, enable_authz: bool = True) -> ScanResult:
    config = ScanConfig(target=root, enable_authz=enable_authz)
    ctx = ScanContext(target_path=root, config=config, result=ScanResult())
    return AuthzPass().run(ctx)


def _bola(result: ScanResult):
    return [f for f in result.findings if f.rule_id == "AUTHZ-BOLA-001"]


class TestTruePositives:
    def test_django_fbv_unowned_read_is_flagged(self):
        root = _make_project({
            "views.py": (
                "def document_detail(request, pk):\n"
                "    doc = Document.objects.get(id=pk)\n"
                "    return render(doc)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert f.category == Category.AUTH
        assert 639 in f.cwe_ids
        assert f.metadata["model"] == "Document"

    def test_drf_cbv_method_unowned_read_is_flagged(self):
        root = _make_project({
            "api.py": (
                "class DocumentView(APIView):\n"
                "    def get(self, request, pk):\n"
                "        return Response(Document.objects.get(id=pk))\n"
                "    def post(self, request):\n"
                "        return Response(request.user.id)\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].metadata["model"] == "Document"

    def test_get_object_or_404_unowned_is_flagged(self):
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    obj = get_object_or_404(Invoice, id=pk)\n"
                "    return obj\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].metadata["model"] == "Invoice"

    def test_flask_route_unowned_read_is_flagged(self):
        root = _make_project({
            "app.py": (
                "@app.route('/doc/<doc_id>')\n"
                "def show(doc_id):\n"
                "    return Document.query.filter_by(id=doc_id).first()\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].metadata["model"] == "Document"

    def test_finding_carries_remediation_guidance(self):
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    return Document.objects.get(id=pk)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert "owner" in findings[0].metadata["remediation"]


class TestTrueNegatives:
    def test_ownership_fused_get_is_not_flagged(self):
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    return Document.objects.get(id=pk, owner=request.user)\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_ownership_fused_filter_chain_is_not_flagged(self):
        # The chain must be reported once at most; fused -> zero, and the inner
        # .filter link must not double-count.
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    return Document.objects.filter(owner=request.user, id=pk).first()\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_get_object_or_404_owner_kwarg_is_not_flagged(self):
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    return get_object_or_404(Invoice, id=pk, owner=request.user)\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_no_principal_concept_is_not_flagged(self):
        # A user-keyed unowned read, but the repo has no notion of a current
        # user anywhere -> this is missing-authentication, not missing-authz.
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    return Document.objects.get(id=pk)\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_constant_keyed_read_is_not_flagged(self):
        root = _make_project({
            "views.py": (
                "def homepage(request):\n"
                "    return Document.objects.get(id=1)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert _bola(_run(root)) == []

    def test_non_handler_function_is_not_flagged(self):
        # A plain helper (no request param, no route decorator, not a CBV method)
        # is not a request handler, so its reads are out of scope.
        root = _make_project({
            "helpers.py": (
                "def load(pk):\n"
                "    return Document.objects.get(id=pk)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert _bola(_run(root)) == []


class TestGating:
    def test_disabled_by_default_emits_nothing(self):
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    return Document.objects.get(id=pk)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert _run(root, enable_authz=False).findings == []

    def test_chained_read_reported_once(self):
        # Unowned chained read -> exactly one finding, at the outermost call.
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    return Document.objects.filter(id=pk).first()\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        findings = _bola(_run(root))
        assert len(findings) == 1


class TestFetchThenGuard:
    """Phase 2 (issue #172): guard-dominates-use via `collect_dominating_candidates`."""

    def test_dominating_combined_existence_and_ownership_guard_suppresses(self):
        # The near-universal `if not obj or obj.owner != principal: deny()`
        # idiom fuses the null check and the ownership check into one
        # BoolOp(Or, ...) test -- a real gap found benchmarking against
        # ModelForge's own update_model handler (#175), which uses exactly
        # this shape and was a false positive before this fix.
        root = _make_project({
            "app.py": (
                "@app.route('/doc/<int:doc_id>')\n"
                "def show(doc_id):\n"
                "    obj = Document.query.get(doc_id)\n"
                "    if not obj or obj.owner_id != g.user_id:\n"
                "        return jsonify(error='not found'), 404\n"
                "    return jsonify(id=obj.id, title=obj.title)\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_dominating_guard_raise_permission_denied_suppresses(self):
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    obj = Document.objects.get(id=pk)\n"
                "    if obj.owner_id != request.user.id:\n"
                "        raise PermissionDenied\n"
                "    return obj.render()\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_dominating_guard_flask_g_user_id_suppresses(self):
        # A minimal Flask idiom distinct from g.user/request.user: a bare
        # int stashed directly on `g` by request-scoped auth, no user object.
        root = _make_project({
            "app.py": (
                "@app.route('/doc/<int:doc_id>')\n"
                "def show(doc_id):\n"
                "    obj = Document.query.get(doc_id)\n"
                "    if obj.owner_id != g.user_id:\n"
                "        return jsonify(error='not found'), 404\n"
                "    return jsonify(id=obj.id)\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_absent_guard_flask_g_user_id_is_flagged(self):
        root = _make_project({
            "app.py": (
                "@app.route('/doc/<int:doc_id>')\n"
                "def show(doc_id):\n"
                "    obj = Document.query.get(doc_id)\n"
                "    return jsonify(id=obj.id)\n"
            ),
            "auth.py": (
                "def load_principal():\n"
                "    g.user_id = int(claims['sub'])\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1

    def test_dominating_guard_abort_403_suppresses(self):
        root = _make_project({
            "app.py": (
                "@app.route('/doc/<doc_id>')\n"
                "def show(doc_id):\n"
                "    obj = Document.query.filter_by(id=doc_id).first()\n"
                "    if obj.owner_id != current_user.id:\n"
                "        abort(403)\n"
                "    return obj.render()\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_dominating_guard_equality_inversion_suppresses(self):
        # if owner == principal: pass else: deny -- the continuation after
        # the whole if/else is only reached when ownership holds.
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    obj = Document.objects.get(id=pk)\n"
                "    if obj.owner_id == request.user.id:\n"
                "        pass\n"
                "    else:\n"
                "        return HttpResponseForbidden()\n"
                "    return obj.render()\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_guard_in_sibling_branch_is_medium(self):
        # The guard lives in a branch that does not lead to the later use.
        root = _make_project({
            "views.py": (
                "def detail(request, pk, mode):\n"
                "    obj = Document.objects.get(id=pk)\n"
                "    if mode == 'strict':\n"
                "        if obj.owner_id != request.user.id:\n"
                "            raise PermissionDenied\n"
                "    return obj.render()\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].metadata["reason"] == "guard_not_dominating"

    def test_guard_absent_entirely_is_high(self):
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    obj = Document.objects.get(id=pk)\n"
                "    return obj.render()\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].metadata["reason"] == "no_guard"

    def test_guard_after_use_is_medium(self):
        # A guard that only appears after the use it should have protected --
        # dead code on the path that reaches the use, so it must not suppress.
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    obj = Document.objects.get(id=pk)\n"
                "    result = obj.render()\n"
                "    if obj.owner_id != request.user.id:\n"
                "        raise PermissionDenied\n"
                "    return result\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].metadata["reason"] == "guard_not_dominating"

    def test_dominating_guard_after_not_found_check_suppresses(self):
        # The near-universal Flask/Django idiom: a bare existence/null check
        # runs immediately after the fetch, before the ownership guard. The
        # null check must not be mistaken for the object's first "use" --
        # otherwise it would mask the real dominating guard written after it.
        root = _make_project({
            "app.py": (
                "@app.route('/doc/<int:doc_id>')\n"
                "def show(doc_id):\n"
                "    obj = Document.query.get(doc_id)\n"
                "    if not obj:\n"
                "        return jsonify(error='not found'), 404\n"
                "    if obj.owner_id != g.user_id:\n"
                "        return jsonify(error='forbidden'), 403\n"
                "    return jsonify(id=obj.id, title=obj.title)\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_absent_guard_after_not_found_check_is_flagged(self):
        root = _make_project({
            "app.py": (
                "@app.route('/doc/<int:doc_id>')\n"
                "def show(doc_id):\n"
                "    obj = Document.query.get(doc_id)\n"
                "    if not obj:\n"
                "        return jsonify(error='not found'), 404\n"
                "    return jsonify(id=obj.id, title=obj.title)\n"
            ),
            "auth.py": (
                "def load_principal():\n"
                "    g.user_id = int(claims['sub'])\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestPhase6Precision:
    """Phase 6: false-positive reduction on concrete benchmark idioms."""

    def test_late_built_payload_guard_before_response_suppresses(self):
        # D50 from the ModelForge BOLA tier: fields are copied into a local
        # payload before the guard, but nothing escapes until the guarded
        # response, so the deny path discards it.
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    note = Note.objects.get(id=pk)\n"
                "    payload = {'id': note.id, 'title': note.title}\n"
                "    if note.owner_id != request.user.id:\n"
                "        return HttpResponseForbidden()\n"
                "    return JsonResponse(payload)\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_pre_guard_side_effect_use_still_medium(self):
        # A local payload is safe to build pre-guard; an externally visible
        # side effect pre-guard is not.
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    note = Note.objects.get(id=pk)\n"
                "    logger.info(note.title)\n"
                "    if note.owner_id != request.user.id:\n"
                "        raise PermissionDenied\n"
                "    return note.render()\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].metadata["reason"] == "guard_not_dominating"

    def test_late_built_jsonify_response_suppresses(self):
        # The real D50 shape: jsonify() reads the fields pre-guard, but the
        # response object is local until the guarded return.
        root = _make_project({
            "app.py": (
                "@app.route('/notes/<int:note_id>/late-built')\n"
                "def show(note_id):\n"
                "    note = Note.query.get(note_id)\n"
                "    payload = jsonify(id=note.id, title=note.title)\n"
                "    if note.owner_id != g.user_id:\n"
                "        return jsonify(error='forbidden'), 403\n"
                "    return payload\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_cross_function_ownership_guard_suppresses(self):
        root = _make_project({
            "views.py": (
                "def require_owner(note):\n"
                "    if note.owner_id != request.user.id:\n"
                "        raise PermissionDenied\n"
                "\n"
                "@app.get('/notes/<pk>')\n"
                "def detail(request, pk):\n"
                "    note = Note.objects.get(id=pk)\n"
                "    require_owner(note)\n"
                "    return note.render()\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_cross_function_guard_after_use_still_medium(self):
        root = _make_project({
            "views.py": (
                "def require_owner(note):\n"
                "    if note.owner_id != request.user.id:\n"
                "        raise PermissionDenied\n"
                "\n"
                "@app.get('/notes/<pk>')\n"
                "def detail(request, pk):\n"
                "    note = Note.objects.get(id=pk)\n"
                "    rendered = note.render()\n"
                "    require_owner(note)\n"
                "    return rendered\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].metadata["reason"] == "guard_not_dominating"

    def test_dominating_superuser_helper_suppresses(self):
        root = _make_project({
            "views.py": (
                "def _require_superuser(user):\n"
                "    if not getattr(user, 'is_superuser', False):\n"
                "        raise PermissionDenied\n"
                "\n"
                "@router.post('/assignments')\n"
                "async def create_assignment(payload, current_user, session):\n"
                "    _require_superuser(current_user)\n"
                "    user = await session.get(User, payload.user_id)\n"
                "    return user.render()\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_non_dominating_superuser_helper_does_not_suppress(self):
        root = _make_project({
            "views.py": (
                "def _require_superuser(user):\n"
                "    if not user.is_superuser:\n"
                "        raise PermissionDenied\n"
                "\n"
                "@router.post('/assignments')\n"
                "def create_assignment(payload, current_user, check):\n"
                "    if check:\n"
                "        _require_superuser(current_user)\n"
                "    user = User.objects.get(id=payload.user_id)\n"
                "    return user.render()\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_late_superuser_helper_does_not_suppress(self):
        root = _make_project({
            "views.py": (
                "def _require_superuser(user):\n"
                "    if not user.is_superuser:\n"
                "        raise PermissionDenied\n"
                "\n"
                "@router.post('/assignments')\n"
                "def create_assignment(payload, current_user):\n"
                "    user = User.objects.get(id=payload.user_id)\n"
                "    _require_superuser(current_user)\n"
                "    return user.render()\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1

    def test_boolean_superuser_helper_does_not_suppress(self):
        root = _make_project({
            "views.py": (
                "def is_superuser(user):\n"
                "    return user.is_superuser\n"
                "\n"
                "@router.post('/assignments')\n"
                "def create_assignment(payload, current_user):\n"
                "    is_superuser(current_user)\n"
                "    user = User.objects.get(id=payload.user_id)\n"
                "    return user.render()\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1

    def test_superuser_helper_on_different_principal_does_not_suppress(self):
        root = _make_project({
            "views.py": (
                "def _require_superuser(user):\n"
                "    if not user.is_superuser:\n"
                "        raise PermissionDenied\n"
                "\n"
                "@router.post('/assignments')\n"
                "def create_assignment(payload, current_user, target_user):\n"
                "    principal_id = current_user.id\n"
                "    _require_superuser(target_user)\n"
                "    user = User.objects.get(id=payload.user_id)\n"
                "    return user.render()\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1

    def test_caught_superuser_helper_does_not_suppress(self):
        root = _make_project({
            "views.py": (
                "def _require_superuser(user):\n"
                "    if not user.is_superuser:\n"
                "        raise PermissionDenied\n"
                "\n"
                "@router.post('/assignments')\n"
                "def create_assignment(payload, current_user):\n"
                "    try:\n"
                "        _require_superuser(current_user)\n"
                "    except PermissionDenied:\n"
                "        pass\n"
                "    user = User.objects.get(id=payload.user_id)\n"
                "    return user.render()\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1

    def test_fail_open_getattr_helper_does_not_suppress(self):
        root = _make_project({
            "views.py": (
                "def _require_superuser(user):\n"
                "    if not getattr(user, 'is_superuser', True):\n"
                "        raise PermissionDenied\n"
                "\n"
                "@router.post('/assignments')\n"
                "def create_assignment(payload, current_user):\n"
                "    _require_superuser(current_user)\n"
                "    user = User.objects.get(id=payload.user_id)\n"
                "    return user.render()\n"
            ),
        })
        findings = _bola(_run(root))
        assert len(findings) == 1


class TestFastAPIEcosystem:
    """Phase 7: FastAPI dependency injection + SQLAlchemy session-query idioms."""

    def test_depends_param_is_not_treated_as_object_id(self):
        root = _make_project({
            "main.py": (
                "@app.get('/settings')\n"
                "def settings(key: str = Depends(setting_key), db: Session = Depends(get_db)):\n"
                "    return db.get(Setting, key)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert _bola(_run(root)) == []

    def test_db_query_filter_unowned_read_is_flagged(self):
        root = _make_project({
            "main.py": (
                "@app.get('/items/{item_id}')\n"
                "def read_item(item_id: int, db: Session = Depends(get_db)):\n"
                "    return db.query(Item).filter(Item.id == item_id).first()\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].metadata["model"] == "Item"

    def test_db_query_positional_owner_filter_suppresses(self):
        root = _make_project({
            "main.py": (
                "@app.get('/items/{item_id}')\n"
                "def read_item(\n"
                "    item_id: int,\n"
                "    current_user: User = Depends(get_current_user),\n"
                "    db: Session = Depends(get_db),\n"
                "):\n"
                "    return db.query(Item).filter(\n"
                "        Item.id == item_id, Item.owner_id == current_user.id\n"
                "    ).first()\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_sqlalchemy_membership_query_guard_suppresses(self):
        root = _make_project({
            "main.py": (
                "@app.get('/invoices/{invoice_id}')\n"
                "def read_invoice(invoice_id: int, db: Session = Depends(get_db)):\n"
                "    invoice = db.query(Invoice).get(invoice_id)\n"
                "    if not db.query(Membership).filter(\n"
                "        Membership.org_id == invoice.org_id,\n"
                "        Membership.user_id == g.user_id,\n"
                "    ).first():\n"
                "        return jsonify(error='forbidden'), 403\n"
                "    return jsonify(id=invoice.id)\n"
            ),
        })
        assert _bola(_run(root)) == []


class TestOtherModels:
    """Phase 3 (issue #173): membership / hierarchical / status models --
    satisfying any one of the four BOLARAY models suppresses the finding."""

    def test_membership_containment_check_dominating_suppresses(self):
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    invoice = Invoice.objects.get(id=pk)\n"
                "    if request.user not in invoice.org.members:\n"
                "        abort(403)\n"
                "    return invoice.render()\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_membership_query_check_dominating_suppresses(self):
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    invoice = Invoice.objects.get(id=pk)\n"
                "    if not Membership.objects.filter(org=invoice.org, user=request.user).exists():\n"
                "        raise PermissionDenied\n"
                "    return invoice.render()\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_membership_absent_is_flagged_with_missing_models(self):
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    invoice = Invoice.objects.get(id=pk)\n"
                "    return invoice.render()\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert "membership" in findings[0].metadata["missing_models"]

    def test_status_fused_read_suppresses(self):
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    return Article.objects.get(id=pk, status='published')\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert _bola(_run(root)) == []

    def test_status_gate_dominating_suppresses(self):
        root = _make_project({
            "views.py": (
                "def detail(request, pk):\n"
                "    article = Article.objects.get(id=pk)\n"
                "    if article.status != 'published':\n"
                "        abort(404)\n"
                "    return article.render()\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert _bola(_run(root)) == []

    def test_hierarchical_related_manager_read_is_invisible_to_extraction(self):
        # NOT a positive guarantee of the hierarchical predicate: this passes
        # because `project.tasks.get(...)` is rooted at a local variable, not
        # a `.objects`/`.query`-marked Model class, so `read_model_class`
        # never recognizes it as an object read at all -- it's a known scope
        # gap (see is_hierarchical_parent_read's docstring), not a case
        # is_hierarchical_parent_read actually resolves. Kept to document the
        # current, honest behavior rather than assert a guarantee that
        # doesn't hold yet.
        root = _make_project({
            "views.py": (
                "def detail(request, project_id, task_id):\n"
                "    project = get_object_or_404(Project, id=project_id, owner=request.user)\n"
                "    task = project.tasks.get(id=task_id)\n"
                "    return task.render()\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_hierarchical_fk_fused_through_authorized_parent_suppresses(self):
        root = _make_project({
            "views.py": (
                "def detail(request, project_id, task_id):\n"
                "    project = get_object_or_404(Project, id=project_id, owner=request.user)\n"
                "    task = Task.objects.get(id=task_id, project=project)\n"
                "    return task.render()\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_hierarchical_fk_fused_via_parent_id_attribute_suppresses(self):
        # The more common Django/SQLAlchemy idiom: the parent's primary key
        # (project.id), not the parent object itself, is what's bound to the
        # FK column.
        root = _make_project({
            "views.py": (
                "def detail(request, project_id, task_id):\n"
                "    project = get_object_or_404(Project, id=project_id, owner=request.user)\n"
                "    task = Task.objects.get(id=task_id, project_id=project.id)\n"
                "    return task.render()\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_hierarchical_absent_raw_child_id_is_flagged(self):
        root = _make_project({
            "views.py": (
                "def detail(request, task_id):\n"
                "    task = Task.objects.get(id=task_id)\n"
                "    return task.render()\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert "hierarchical" in findings[0].metadata["missing_models"]


class TestDecoratorGates:
    """Phase 3 (issue #173): function/class-level authorization gates."""

    def test_drf_object_level_permission_suppresses(self):
        root = _make_project({
            "api.py": (
                "class DocumentView(APIView):\n"
                "    permission_classes = [IsOwner]\n"
                "    def has_object_permission(self, request, view, obj):\n"
                "        return obj.owner == request.user\n"
                "    def get(self, request, pk):\n"
                "        return Response(Document.objects.get(id=pk))\n"
            ),
        })
        assert _bola(_run(root)) == []

    def test_login_required_only_downgrades_to_medium(self):
        root = _make_project({
            "views.py": (
                "@login_required\n"
                "def detail(request, pk):\n"
                "    return Document.objects.get(id=pk)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].metadata["reason"] == "route_decorator_only"

    def test_permission_required_mixin_only_downgrades_to_medium(self):
        root = _make_project({
            "views.py": (
                "class DocumentView(PermissionRequiredMixin, View):\n"
                "    def get(self, request, pk):\n"
                "        return Document.objects.get(id=pk)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].metadata["reason"] == "route_decorator_only"


class TestPrincipalAliases:
    """Phase 4 (#172): resolve names that hold the principal without being one
    of the framework-canonical bases. Real apps bind the principal once -- in
    an auth decorator, a FastAPI dependency, or a local -- and authorize
    against that name, so an unresolved alias turns every genuine ownership
    check into a false positive."""

    _DECORATOR_UTIL = (
        "from functools import wraps\n"
        "def add_tenant_id_to_kwargs(func):\n"
        "    @wraps(func)\n"
        "    def wrapper(**kwargs):\n"
        "        kwargs['tenant_id'] = current_user.id\n"
        "        return func(**kwargs)\n"
        "    return wrapper\n"
    )

    def test_decorator_injected_principal_suppresses_fused_read(self):
        """The decorator that binds the principal lives in another module --
        the ragflow `@add_tenant_id_to_kwargs` shape."""
        root = _make_project({
            "utils.py": self._DECORATOR_UTIL,
            "views.py": (
                "@manager.route('/datasets/<dataset_id>', methods=['GET'])\n"
                "@add_tenant_id_to_kwargs\n"
                "def get_dataset(tenant_id, dataset_id):\n"
                "    return Knowledgebase.objects.get(id=dataset_id, tenant_id=tenant_id)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert _bola(_run(root)) == []

    def test_unresolved_decorator_still_reports(self):
        """Same handler, but nothing in the corpus binds `tenant_id` to the
        principal -- the read must still be reported."""
        root = _make_project({
            "views.py": (
                "@manager.route('/datasets/<dataset_id>', methods=['GET'])\n"
                "@some_unrelated_decorator\n"
                "def get_dataset(tenant_id, dataset_id):\n"
                "    return Knowledgebase.objects.get(id=dataset_id)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert len(_bola(_run(root))) == 1

    def test_fastapi_depends_current_user_is_principal(self):
        root = _make_project({
            "views.py": (
                "@router.get('/docs/{doc_id}')\n"
                "def read_doc(doc_id: str, user = Depends(get_current_user)):\n"
                "    return Document.objects.get(id=doc_id, owner_id=user.id)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert _bola(_run(root)) == []

    def test_fastapi_depends_non_principal_dependency_still_reports(self):
        """`Depends(get_target_user)` is not the caller -- treating any
        dependency as the principal would hide real findings."""
        root = _make_project({
            "views.py": (
                "@router.get('/docs/{doc_id}')\n"
                "def read_doc(doc_id: str, subject = Depends(get_target_user)):\n"
                "    return Document.objects.get(id=doc_id, owner_id=subject.id)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert len(_bola(_run(root))) == 1

    def test_local_alias_of_principal(self):
        root = _make_project({
            "views.py": (
                "@app.get('/docs/<doc_id>')\n"
                "def read_doc(doc_id):\n"
                "    uid = current_user.id\n"
                "    return Document.objects.get(id=doc_id, owner_id=uid)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert _bola(_run(root)) == []

    def test_injected_principal_is_not_attacker_controlled(self):
        """A server-injected principal parameter must not itself make a read
        look attacker-keyed."""
        root = _make_project({
            "utils.py": self._DECORATOR_UTIL,
            "views.py": (
                "@manager.route('/mine', methods=['GET'])\n"
                "@add_tenant_id_to_kwargs\n"
                "def list_mine(tenant_id):\n"
                "    return Knowledgebase.objects.get(tenant_id=tenant_id)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert _bola(_run(root)) == []


class TestFusedGuardAuthorizesParentId:
    """Phase 4 (#172): `if not Parent.query(id=pid, owner=principal): deny`
    authorizes `pid` for the rest of the handler even though nothing is
    assigned -- the service-layer idiom `_authorized_parent_vars`' original
    assignment shape could not see."""

    _DECORATOR_UTIL = TestPrincipalAliases._DECORATOR_UTIL

    def test_fused_guard_authorizes_child_read(self):
        root = _make_project({
            "utils.py": self._DECORATOR_UTIL,
            "views.py": (
                "@manager.route('/datasets/<dataset_id>/docs/<doc_id>', methods=['GET'])\n"
                "@add_tenant_id_to_kwargs\n"
                "def get_doc(tenant_id, dataset_id, doc_id):\n"
                "    if not Knowledgebase.objects.filter(id=dataset_id, tenant_id=tenant_id):\n"
                "        return error('you do not own the dataset')\n"
                "    return Document.objects.get(kb_id=dataset_id, id=doc_id)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert _bola(_run(root)) == []

    def test_guard_without_principal_does_not_authorize(self):
        """An existence-only guard proves the row exists, not that it is the
        caller's -- this is ragflow's `download` bug (H1) and must report.

        The unguarded parent read is reported too, which is correct; this
        asserts specifically that the *child* read is not suppressed.
        """
        root = _make_project({
            "utils.py": self._DECORATOR_UTIL,
            "views.py": (
                "@manager.route('/datasets/<dataset_id>/docs/<doc_id>', methods=['GET'])\n"
                "@add_tenant_id_to_kwargs\n"
                "def get_doc(tenant_id, dataset_id, doc_id):\n"
                "    if not Knowledgebase.objects.filter(id=dataset_id):\n"
                "        return error('no such dataset')\n"
                "    return Document.objects.get(kb_id=dataset_id, id=doc_id)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        models = [f.metadata.get("model") for f in _bola(_run(root))]
        assert "Document" in models, f"child read must still be reported, got {models}"

    def test_non_denying_guard_does_not_authorize(self):
        """The guard must actually deny; a logging-only branch proves nothing."""
        root = _make_project({
            "utils.py": self._DECORATOR_UTIL,
            "views.py": (
                "@manager.route('/datasets/<dataset_id>/docs/<doc_id>', methods=['GET'])\n"
                "@add_tenant_id_to_kwargs\n"
                "def get_doc(tenant_id, dataset_id, doc_id):\n"
                "    if not Knowledgebase.objects.filter(id=dataset_id, tenant_id=tenant_id):\n"
                "        log.warning('missing')\n"
                "    return Document.objects.get(kb_id=dataset_id, id=doc_id)\n"
            ),
            "auth.py": _PRINCIPAL_FILE,
        })
        assert len(_bola(_run(root))) == 1


def test_guard_before_rebinding_does_not_cover_second_read():
    """AZ-14: the guard checked the first `obj`, not the re-read one."""
    root = _make_project({
        "views.py": (
            "def detail(request, pk, other_id):\n"
            "    obj = Document.objects.get(id=pk)\n"
            "    if obj.owner_id != request.user.id:\n"
            "        raise PermissionDenied\n"
            "    obj = Document.objects.get(id=other_id)\n"
            "    return obj.render()\n"
        ),
        "auth.py": _PRINCIPAL_FILE,
    })
    assert [f.start_line for f in _bola(_run(root))] == [6]


def test_deny_branch_that_returns_object_is_not_a_guard():
    """AZ-15: a 'deny' that hands back the object guards nothing."""
    root = _make_project({
        "views.py": (
            "def detail(request, pk):\n"
            "    obj = Document.objects.get(id=pk)\n"
            "    if obj.owner_id != request.user.id:\n"
            "        return render(request, 'preview.html', {'doc': obj})\n"
            "    return obj.render()\n"
        ),
        "auth.py": _PRINCIPAL_FILE,
    })
    found = _bola(_run(root))
    assert [f.severity for f in found] == [Severity.HIGH]


def test_deny_branch_without_the_object_is_still_a_guard():
    root = _make_project({
        "views.py": (
            "def detail(request, pk):\n"
            "    obj = Document.objects.get(id=pk)\n"
            "    if obj.owner_id != request.user.id:\n"
            "        return JsonResponse({'error': 'forbidden'}, status=403)\n"
            "    return obj.render()\n"
        ),
        "auth.py": _PRINCIPAL_FILE,
    })
    assert _bola(_run(root)) == []


def test_status_kwarg_from_request_does_not_fuse():
    """AZ-17: `state=request.args` is user input, not a literal state constraint."""
    root = _make_project({
        "views.py": (
            "def detail(request, pk):\n"
            "    return Document.objects.get(id=pk, state=request.GET)\n"
            "def published(request, pk):\n"
            "    return Document.objects.get(id=pk, status=Status.PUBLISHED)\n"
            "def qualified(request, pk):\n"
            "    return Document.objects.get(id=pk, status=models.Status.PUBLISHED)\n"
        ),
        "auth.py": _PRINCIPAL_FILE,
    })
    assert [f.start_line for f in _bola(_run(root))] == [3]


def test_deny_redirect_carrying_only_the_id_is_still_a_guard():
    """AZ-15 must not turn this into HIGH no_guard. It stays MEDIUM because the
    escape finder counts `obj.pk` in the return as an escape (as on main)."""
    root = _make_project({
        "views.py": (
            "def detail(request, pk):\n"
            "    obj = Document.objects.get(id=pk)\n"
            "    if obj.owner_id != request.user.id:\n"
            "        return redirect('request-access', pk=obj.pk)\n"
            "    return obj.render()\n"
        ),
        "auth.py": _PRINCIPAL_FILE,
    })
    assert [f.severity for f in _bola(_run(root))] == [Severity.MEDIUM]


def test_status_kwarg_named_constant_still_fuses():
    root = _make_project({
        "views.py": (
            "def detail(request, pk):\n"
            "    return Document.objects.get(id=pk, status=self.PUBLISHED)\n"
        ),
        "auth.py": _PRINCIPAL_FILE,
    })
    assert _bola(_run(root)) == []


_HELPER_APP = (
    "import repo\n"
    "@app.route('/memos/<int:memo_id>')\n"
    "def read_memo(memo_id):\n"
    "    memo = repo.fetch_memo(memo_id)\n"
    "{guard}"
    "    return jsonify(body=memo.body)\n"
)
_PRINCIPAL = {"auth.py": "def load_principal():\n    g.user_id = int(claims['sub'])\n"}


class TestReadThroughHelper:
    """#4: the unguarded read lives in a helper in another module."""

    def test_unguarded_read_through_repo_helper_is_flagged(self):
        root = _make_project({
            "repo.py": "def fetch_memo(memo_id):\n    return db.session.get(Memo, memo_id)\n",
            "app.py": _HELPER_APP.format(guard=""),
            **_PRINCIPAL,
        })
        findings = _bola(_run(root))
        assert len(findings) == 1
        assert findings[0].metadata["model"] == "Memo"

    def test_from_import_helper_is_flagged(self):
        root = _make_project({
            "repo.py": "def fetch_memo(memo_id):\n    return Memo.query.get(memo_id)\n",
            "app.py": (
                "from repo import fetch_memo\n"
                "@app.route('/memos/<int:memo_id>')\n"
                "def read_memo(memo_id):\n"
                "    memo = fetch_memo(memo_id)\n"
                "    return jsonify(body=memo.body)\n"
            ),
            **_PRINCIPAL,
        })
        assert len(_bola(_run(root))) == 1

    def test_handler_ownership_guard_after_helper_suppresses(self):
        root = _make_project({
            "repo.py": "def fetch_memo(memo_id):\n    return db.session.get(Memo, memo_id)\n",
            "app.py": _HELPER_APP.format(
                guard="    if memo.owner_id != g.user_id:\n        abort(403)\n"
            ),
            **_PRINCIPAL,
        })
        assert _bola(_run(root)) == []

    def test_helper_that_checks_the_principal_is_not_flagged(self):
        root = _make_project({
            "repo.py": (
                "def fetch_memo(memo_id):\n"
                "    memo = db.session.get(Memo, memo_id)\n"
                "    if memo.owner_id != g.user_id:\n"
                "        abort(403)\n"
                "    return memo\n"
            ),
            "app.py": _HELPER_APP.format(guard=""),
            **_PRINCIPAL,
        })
        assert _bola(_run(root)) == []

    def test_helper_with_ownership_fused_query_is_not_flagged(self):
        root = _make_project({
            "repo.py": (
                "def fetch_memo(memo_id):\n"
                "    return Memo.query.filter_by(id=memo_id, owner_id=g.user_id).first()\n"
            ),
            "app.py": _HELPER_APP.format(guard=""),
            **_PRINCIPAL,
        })
        assert _bola(_run(root)) == []

    def test_helper_not_keyed_by_the_request_id_is_not_flagged(self):
        root = _make_project({
            "repo.py": "def latest_memo(limit):\n    return db.session.get(Memo, 1)\n",
            "app.py": _HELPER_APP.format(guard="").replace(
                "repo.fetch_memo(memo_id)", "repo.latest_memo(10)"
            ),
            **_PRINCIPAL,
        })
        assert _bola(_run(root)) == []

    def test_principal_passed_to_helper_as_argument_is_not_flagged(self):
        root = _make_project({
            "repo.py": (
                "def fetch_memo(memo_id, owner):\n"
                "    return Memo.query.filter_by(id=memo_id, owner_id=owner).first()\n"
            ),
            "app.py": _HELPER_APP.format(guard="").replace(
                "repo.fetch_memo(memo_id)", "repo.fetch_memo(memo_id, g.user_id)"
            ),
            **_PRINCIPAL,
        })
        assert _bola(_run(root)) == []


def _repository_case(tmp_path, helper, route):
    files = {
        'site/handlers.py': "from . import storage as data\n@app.get('/objects/<int:key>')\ndef show(key):\n" + route,
        'site/storage.py': "from .primitive import retrieve\n" + helper,
        'site/primitive.py': "def retrieve(entity, identifier):\n    return db.session.get(entity, identifier)\n",
        'site/identity.py': "def principal():\n    return g.account_id\n",
    }
    for name, code in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code)
    return _bola(_run(tmp_path))


def test_alias_and_generic_two_hop_repository_read(tmp_path):
    assert _repository_case(tmp_path,
        'def lookup(key):\n    return retrieve(Invoice, key)\n',
        '    item = data.lookup(key)\n    return jsonify(value=item.amount)\n')


def test_returned_permission_pair_is_checked_at_caller(tmp_path):
    assert not _repository_case(tmp_path,
        'def lookup(key, actor):\n    item = retrieve(Invoice, key)\n    return item, item.owner_id == actor\n',
        '    item, permitted = data.lookup(key, g.account_id)\n    if not permitted:\n        return "denied", 403\n    return jsonify(value=item.amount)\n')


def test_returned_permission_pair_without_caller_guard_is_reported(tmp_path):
    assert _repository_case(tmp_path,
        'def lookup(key, actor):\n    item = retrieve(Invoice, key)\n    return item, item.owner_id == actor\n',
        '    item, permitted = data.lookup(key, g.account_id)\n    return jsonify(value=item.amount)\n')


def test_conditional_returned_permission_is_not_proof(tmp_path):
    assert _repository_case(tmp_path,
        'def lookup(key, actor, enforce):\n    item = retrieve(Invoice, key)\n    allowed = not (enforce and item.owner_id != actor)\n    return item, allowed\n',
        '    item, permitted = data.lookup(key, g.account_id, request.args.get("check"))\n    if not permitted:\n        return "denied", 403\n    return jsonify(value=item.amount)\n')


def test_repository_status_gate_returning_none_is_safe(tmp_path):
    assert not _repository_case(tmp_path,
        'def lookup(key):\n    item = retrieve(Invoice, key)\n    if item is None or item.status != "published":\n        return None\n    return item\n',
        '    item = data.lookup(key)\n    if item is None:\n        return "missing", 404\n    return jsonify(value=item.amount)\n')


def test_repository_parent_scope_positional_filter_is_safe(tmp_path):
    assert not _repository_case(tmp_path,
        'def lookup(key, actor):\n    parent = Folder.query.filter(Folder.owner_id == actor).first()\n    if parent is None:\n        return None\n    return Invoice.query.filter(Invoice.id == key, Invoice.folder_id == parent.id).first()\n',
        '    item = data.lookup(key, g.account_id)\n    return jsonify(value=item.amount)\n')


def test_unresolved_external_object_read_is_coverage_not_bola(tmp_path):
    (tmp_path / 'api.py').write_text('''
from vendor import client
@app.get('/items/<int:key>')
def show(key):
    item = client.lookup(key)
    return jsonify(value=item.amount)
def identity():
    return request.user.id
''')
    result = _run(tmp_path)
    assert not _bola(result)
    signals = [f for f in result.findings if f.rule_id == 'AUTHZ-UNVERIFIED-001']
    assert len(signals) == 1
    assert signals[0].severity == Severity.INFO
    assert signals[0].metadata['coverage_signal']


def test_returned_permission_cannot_mutate_owner_to_authorize_itself(tmp_path):
    assert _repository_case(tmp_path,
        'def lookup(key, actor):\n    item = retrieve(Invoice, key)\n    item.owner_id = actor\n    return item, item.owner_id == actor\n',
        '    item, permitted = data.lookup(key, g.account_id)\n    if not permitted:\n        return "denied", 403\n    return jsonify(value=item.amount)\n')


def test_boolean_helper_does_not_hide_earlier_object_disclosure(tmp_path):
    assert _repository_case(tmp_path,
        'def lookup(key, actor):\n    item = retrieve(Invoice, key)\n    publish(item.amount)\n    return item.owner_id == actor\n',
        '    allowed = data.lookup(key, g.account_id)\n    return jsonify(allowed=allowed)\n')
