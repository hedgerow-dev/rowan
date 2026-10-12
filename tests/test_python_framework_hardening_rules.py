"""Regression tests for framework-independent LangChain-derived bug classes."""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
TAINT_RULES = RULES_DIR / "python_framework_hardening_taint.yaml"
SEARCH_RULES = RULES_DIR / "python_framework_hardening_opengrep.yaml"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(), reason="Opengrep binary is required"
)


def _scan(tmp_path: Path, source: str, rule_file: Path, rule_id: str):
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [rule_file], languages=["python"]
    )
    return [finding for finding in findings if finding.rule_id == rule_id]


class TestObjectRevival:
    def test_unescaped_object_marker_serializer_is_flagged_without_framework_name(self, tmp_path):
        source = """
import json

def encode_special(value):
    if isinstance(value, SerializableObject):
        return value.to_json()
    raise TypeError()

def serialize(value):
    return json.dumps(value, default=encode_special)
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-UNESCAPED-OBJECT-MARKER-001")

    def test_marker_escaping_before_encoding_is_clean(self, tmp_path):
        source = """
import json

def encode_special(value):
    if isinstance(value, SerializableObject):
        return value.to_json()
    raise TypeError()

def serialize(value):
    escaped = escape_marker_dicts(value)
    return json.dumps(escaped, default=encode_special)
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-UNESCAPED-OBJECT-MARKER-001")

    def test_plain_json_default_handler_is_not_object_marker_signal(self, tmp_path):
        source = """
import json

def serialize(value):
    return json.dumps(value, default=str)
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-UNESCAPED-OBJECT-MARKER-001")

    def test_generic_object_loader_from_request_is_flagged(self, tmp_path):
        source = """
from flask import request
import framework.serialization

def restore():
    value = request.get_json()
    encoded = framework.serialization.dumps(value)
    return framework.serialization.loads(encoded)
"""
        assert _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-DESER-001")

    def test_json_data_parser_is_not_object_revival(self, tmp_path):
        source = """
from flask import request
import json

def restore():
    return json.loads(request.data)
"""
        assert not _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-DESER-001")

    def test_broad_allowlist_is_framework_independent(self, tmp_path):
        source = 'result = runtime.restore(payload, allowed_objects="all")\n'
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-BROAD-ALLOWLIST-001")

    def test_explicit_allowlist_is_not_flagged(self, tmp_path):
        source = "result = runtime.restore(payload, allowed_objects=[Message])\n"
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-BROAD-ALLOWLIST-001")


class TestConfinedPaths:
    def test_config_derived_template_path_read_is_flagged(self, tmp_path):
        source = """
from pathlib import Path

def read_template(config):
    filename = Path(config.pop("template_path"))
    if filename.suffix == ".txt":
        return filename.read_text()
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-UNCONFINED-CONFIG-PATH-001")

    def test_config_derived_examples_open_is_flagged(self, tmp_path):
        source = """
from pathlib import Path

def read_examples(settings):
    filename = Path(settings["examples"])
    with filename.open() as handle:
        return handle.read()
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-UNCONFINED-CONFIG-PATH-001")

    def test_config_path_forwarded_to_loader_is_flagged(self, tmp_path):
        source = """
def read_example(settings):
    return load_template(settings.pop("example_prompt_path"))
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-UNCONFINED-CONFIG-PATH-001")

    def test_config_path_validation_before_read_is_clean(self, tmp_path):
        source = """
from pathlib import Path

def read_template(config):
    filename = Path(config.pop("template_path"))
    validate_relative_path(filename)
    return filename.read_text()
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-UNCONFINED-CONFIG-PATH-001")

    def test_config_path_validation_after_read_still_flags(self, tmp_path):
        source = """
from pathlib import Path

def read_template(config):
    filename = Path(config.pop("template_path"))
    content = filename.read_text()
    validate_relative_path(filename)
    return content
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-UNCONFINED-CONFIG-PATH-001")

    def test_non_path_config_value_to_loader_is_clean(self, tmp_path):
        source = """
def read_example(settings):
    return load_template(settings.pop("template_data"))
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-UNCONFINED-CONFIG-PATH-001")

    def test_generic_file_search_pattern_is_flagged(self, tmp_path):
        source = """
from flask import request

def search(index):
    pattern = request.args["pattern"]
    return index.search_files(pattern=pattern, path="/srv/data")
"""
        assert _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-PATH-001")

    def test_generic_config_loader_is_flagged(self, tmp_path):
        source = """
from flask import request

def load():
    return load_config(request.args["path"])
"""
        assert _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-PATH-001")

    def test_constant_loader_path_is_not_flagged(self, tmp_path):
        source = 'result = load_config("/srv/app/config.json")\n'
        assert not _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-PATH-001")

    def test_unconfined_glob_match_is_flagged(self, tmp_path):
        source = """
def find_files(root, pattern):
    for match in root.glob(pattern):
        if match.is_file():
            yield match.read_text()
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-GLOB-UNCONFINED-MATCH-001")

    def test_glob_match_with_resolved_containment_is_clean(self, tmp_path):
        source = """
def find_files(root, pattern):
    for match in root.glob(pattern):
        if match.is_file() and _is_within_root(match, root):
            yield match.read_text()
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-GLOB-UNCONFINED-MATCH-001")

    def test_raw_prefix_check_is_flagged(self, tmp_path):
        source = """
def allowed(path, allowed_prefixes):
    return any(path.startswith(prefix) for prefix in allowed_prefixes)
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-RAW-PATH-PREFIX-001")

    def test_segment_bounded_prefix_is_clean(self, tmp_path):
        source = """
def allowed(path, allowed_prefixes):
    return any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in allowed_prefixes)
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-RAW-PATH-PREFIX-001")

class TestIndirectUrlFetch:
    def test_url_document_helper_is_flagged(self, tmp_path):
        source = """
from flask import request

def split(splitter):
    return splitter.split_text_from_url(request.args["url"])
"""
        assert _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-URLFETCH-001")

    def test_nested_media_url_to_token_counter_is_flagged(self, tmp_path):
        source = """
from flask import request

def count(model):
    url = request.get_json()["image_url"]
    messages = [{"content": [{"type": "image_url", "url": url}]}]
    return model.get_num_tokens_from_messages(messages)
"""
        assert _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-IMAGECOUNT-001")

    def test_text_token_count_does_not_imply_url_fetch(self, tmp_path):
        source = """
from flask import request

def count(model):
    question = request.get_json()["question"]
    return model.get_num_tokens_from_messages([{"role": "user", "content": question}])
"""
        assert not _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-IMAGECOUNT-001")
        assert not _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-URLFETCH-001")

    def test_constant_document_url_is_not_flagged(self, tmp_path):
        source = 'docs = splitter.split_text_from_url("https://docs.example/page")\n'
        assert not _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-URLFETCH-001")

    @pytest.mark.parametrize("client", ["requests", "httpx"])
    def test_validation_then_separate_fetch_is_flagged(self, tmp_path, client):
        source = f"""
def fetch(url):
    validate_safe_url(url)
    return {client}.get(url)
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-SSRF-TOCTOU-001")

    def test_guarded_fetch_is_not_flagged(self, tmp_path):
        source = """
def fetch(url):
    return ssrf_safe_get(url)
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-SSRF-TOCTOU-001")

    def test_allowlist_then_redirecting_fetch_uses_toctou_rule(self, tmp_path):
        source = """
def fetch(url):
    if not host_allowed(url):
        raise ValueError("blocked")
    return requests.get(url, allow_redirects=True)
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-SSRF-TOCTOU-001")
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-URL-PARAM-FETCH-001")

    def test_dns_pinned_fetch_is_not_a_direct_surface_signal(self, tmp_path):
        source = """
def fetch(url):
    infos = socket.getaddrinfo(urlparse(url).hostname, None)
    validate_public_addresses(infos)
    return requests.get(url, allow_redirects=False)
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-URL-PARAM-FETCH-001")

    def test_library_helper_directly_fetching_url_parameter_is_flagged(self, tmp_path):
        source = """
def image_size(image_url):
    return httpx.get(image_url).content
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-URL-PARAM-FETCH-001")

    def test_validated_fetch_uses_toctou_rule_not_direct_fetch_rule(self, tmp_path):
        source = """
def image_size(image_url):
    validate_safe_url(image_url)
    return httpx.get(image_url).content
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-URL-PARAM-FETCH-001")
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-SSRF-TOCTOU-001")


class TestDynamicFormatPrograms:
    def test_request_controlled_python_format_string_is_flagged(self, tmp_path):
        source = """
from flask import request

def render(context):
    template = request.get_json()["template"]
    return template.format_map(context)
"""
        assert _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-TEMPLATE-001")

    def test_request_controlled_framework_template_is_flagged(self, tmp_path):
        source = """
from flask import request

def build(TemplateEngine):
    template = request.args["template"]
    return TemplateEngine(template=template)
"""
        assert _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-TEMPLATE-001")

    def test_constant_template_with_untrusted_value_is_not_flagged(self, tmp_path):
        source = """
from flask import request

def render():
    value = request.args["value"]
    return "Hello {name}".format(name=value)
"""
        assert not _scan(tmp_path, source, TAINT_RULES, "TNT-PY-FWK-TEMPLATE-001")


class TestLibraryFormatValidation:
    def test_unvalidated_formatter_fields_are_flagged_without_framework_name(self, tmp_path):
        source = """
from string import Formatter

def extract_fields(pattern, kind):
    if kind == "python":
        fields = {name for _, name, _, _ in Formatter().parse(pattern) if name is not None}
    else:
        fields = set()
    return sorted(fields)
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-UNVALIDATED-FORMAT-FIELD-001")

    def test_simple_identifier_guard_closes_field_traversal_signal(self, tmp_path):
        source = """
from string import Formatter

def extract_fields(pattern):
    fields = {name for _, name, _, _ in Formatter().parse(pattern) if name is not None}
    for name in fields:
        if not name.isidentifier():
            raise ValueError("unsafe field")
    return sorted(fields)
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-UNVALIDATED-FORMAT-FIELD-001")

    def test_top_level_guard_with_discarded_spec_is_flagged(self, tmp_path):
        source = """
from string import Formatter

def extract_fields(pattern):
    fields = {name for _, name, _, _ in Formatter().parse(pattern) if name is not None}
    for name in fields:
        if "." in name or "[" in name or "]" in name:
            raise ValueError("unsafe field")
    return sorted(fields)
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-DISCARDED-FORMAT-SPEC-001")
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-UNVALIDATED-FORMAT-FIELD-001")

    def test_checked_format_spec_is_not_discarded(self, tmp_path):
        source = """
from string import Formatter

def extract_fields(pattern):
    fields = []
    for _, name, spec, _ in Formatter().parse(pattern):
        if name is None:
            continue
        if "." in name or "[" in name or "]" in name:
            raise ValueError("unsafe field")
        if spec and ("{" in spec or "}" in spec):
            raise ValueError("nested field")
        fields.append(name)
    return sorted(fields)
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-DISCARDED-FORMAT-SPEC-001")


class TestReviewProbes53:
    """Shapes from the #53 review of the structural framework rules."""

    def test_non_url_parameter_is_not_a_url_fetch(self, tmp_path):
        source = """
def api_client_get(self, endpoint):
    return requests.get(endpoint)
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-URL-PARAM-FETCH-001")

    def test_url_parameter_post_is_a_url_fetch(self, tmp_path):
        source = """
def push(webhook_url, body):
    return requests.post(webhook_url, json=body)
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-URL-PARAM-FETCH-001")

    def test_toctou_is_reported_on_the_fetch_line(self, tmp_path):
        source = """
def fetch(url):
    validate_safe_url(url)
    r = requests.get(url, timeout=3)
    return r
"""
        findings = _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-SSRF-TOCTOU-001")
        assert [f.start_line for f in findings] == [4]

    def test_constant_glob_pattern_is_not_flagged(self, tmp_path):
        source = """
def load(root):
    for p in root.glob("*.json"):
        if p.is_file():
            yield p.read_text()
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-GLOB-UNCONFINED-MATCH-001")

    def test_rglob_with_variable_pattern_is_flagged(self, tmp_path):
        source = """
def find_files(root, pattern):
    for match in root.rglob(pattern):
        if match.is_file():
            yield match.read_text()
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-GLOB-UNCONFINED-MATCH-001")

    @pytest.mark.parametrize(
        "check",
        [
            "os.path.realpath(path).startswith(BASE_DIR)",
            "os.path.abspath(path).startswith(BASE_DIR)",
            "str(Path(path).resolve()).startswith(BASE_DIR)",
        ],
    )
    def test_resolved_path_raw_prefix_is_flagged(self, tmp_path, check):
        source = f"""
import os
from pathlib import Path

def read(path):
    if not {check}:
        raise ValueError("outside")
    return open(path).read()
"""
        assert _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-RAW-PATH-PREFIX-001")

    @pytest.mark.parametrize(
        "check",
        [
            "os.path.realpath(path).startswith(BASE_DIR + os.sep)",
            "os.path.realpath(path).startswith(os.path.join(BASE_DIR, ''))",
        ],
    )
    def test_separator_bounded_prefix_is_clean(self, tmp_path, check):
        source = f"""
import os

def read(path):
    if not {check}:
        raise ValueError("outside")
    return open(path).read()
"""
        assert not _scan(tmp_path, source, SEARCH_RULES, "PY-FWK-RAW-PATH-PREFIX-001")
