"""Behavioral fixtures for the six LC-HARDEN-* LangChain hardening rules.

Three search-mode rules live in rules/langchain_hardening_opengrep.yaml:
  LC-HARDEN-DESER-001           allow_dangerous_deserialization=True   (CWE-502)
  LC-HARDEN-JINJA-FEWSHOT-001   template_format="jinja2" construct     (CWE-1336/94)
  LC-HARDEN-VECTORFILTER-001    non-literal similarity_search filter   (CWE-943)

Three taint-mode rules live in rules/langchain_hardening_taint.yaml:
  LC-HARDEN-TAINT-PROMPTLOAD-001  request -> load_prompt() path         (CWE-22)
  LC-HARDEN-TAINT-CYPHER-001      request -> GraphCypherQAChain.invoke  (CWE-943)
  LC-HARDEN-TAINT-JINJA-001       request -> jinja2 PromptTemplate.format(CWE-1336/94)

Each rule gets a POSITIVE case (a minimal snippet modeling the vuln, asserted
to fire) and a NEGATIVE/safe case (the corresponding safe pattern, asserted not
to fire). The taint cases carry their source in-file (an untrusted function
parameter) so the flow resolves in a single tmp file, matching the rules' own
single-file source pattern.

Requires the Opengrep binary; skipped entirely if not installed, matching the
project convention in tests/test_vector_query_dsl_injection.py (CI does not
install it, see .github/workflows/ci.yml).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
SEARCH_RULES = "langchain_hardening_opengrep.yaml"
TAINT_RULES = "langchain_hardening_taint.yaml"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, source, rule_file, rule_id, languages=("python",)):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [RULES_DIR / rule_file], languages=list(languages))
    return [f for f in findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# LC-HARDEN-DESER-001  (search): allow_dangerous_deserialization=True
# ---------------------------------------------------------------------------
class TestDeserialization:
    def test_dangerous_deser_true_flagged(self, tmp_path):
        src = (
            "def load(p, emb):\n"
            "    return FAISS.load_local(p, emb, allow_dangerous_deserialization=True)\n"
        )
        findings = _scan(tmp_path, "deser_pos.py", src, SEARCH_RULES, "LC-HARDEN-DESER-001")
        assert findings, "allow_dangerous_deserialization=True must be flagged"

    def test_dangerous_deser_false_not_flagged(self, tmp_path):
        src = (
            "def load(p, emb):\n"
            "    return FAISS.load_local(p, emb, allow_dangerous_deserialization=False)\n"
        )
        findings = _scan(tmp_path, "deser_neg.py", src, SEARCH_RULES, "LC-HARDEN-DESER-001")
        assert findings == [], (
            "allow_dangerous_deserialization=False is the safe path and must not be flagged"
        )


# ---------------------------------------------------------------------------
# LC-HARDEN-JINJA-FEWSHOT-001  (search): template_format="jinja2" construct
# ---------------------------------------------------------------------------
class TestJinjaTemplateFormat:
    def test_jinja2_template_format_flagged(self, tmp_path):
        src = (
            "def build():\n"
            "    return PromptTemplate(\n"
            "        input_variables=['q'],\n"
            "        template='{{ q }}',\n"
            "        template_format='jinja2',\n"
            "    )\n"
        )
        findings = _scan(tmp_path, "jinja_pos.py", src, SEARCH_RULES, "LC-HARDEN-JINJA-FEWSHOT-001")
        assert findings, "template_format='jinja2' construct must be flagged"

    def test_default_template_format_not_flagged(self, tmp_path):
        # Default (f-string) format: {var} is data, not evaluated template code.
        src = (
            "def build():\n"
            "    return PromptTemplate(\n"
            "        input_variables=['q'],\n"
            "        template='{q}',\n"
            "    )\n"
        )
        findings = _scan(tmp_path, "jinja_neg.py", src, SEARCH_RULES, "LC-HARDEN-JINJA-FEWSHOT-001")
        assert findings == [], (
            "the default (f-string) template_format is the safe path and must not be flagged"
        )


# ---------------------------------------------------------------------------
# LC-HARDEN-VECTORFILTER-001  (search): non-literal similarity_search filter
# ---------------------------------------------------------------------------
class TestVectorFilter:
    def test_variable_filter_flagged(self, tmp_path):
        # Filter assembled by string concatenation, passed as a variable.
        src = (
            "def search(store, tenant_id, category):\n"
            "    flt = 'category == \"' + category + '\" and tenant == \"' + tenant_id + '\"'\n"
            "    return store.similarity_search('q', k=5, filter=flt)\n"
        )
        findings = _scan(
            tmp_path, "vfilter_pos.py", src, SEARCH_RULES, "LC-HARDEN-VECTORFILTER-001"
        )
        assert findings, "a non-literal (variable) similarity_search filter must be flagged"

    def test_literal_dict_filter_not_flagged(self, tmp_path):
        # Inline scoped literal dict: excluded by the rule's pattern-not.
        src = (
            "def search(store, tenant_id):\n"
            "    return store.similarity_search('q', k=5, filter={'tenant': tenant_id})\n"
        )
        findings = _scan(
            tmp_path, "vfilter_neg.py", src, SEARCH_RULES, "LC-HARDEN-VECTORFILTER-001"
        )
        assert findings == [], (
            "an inline scoped literal dict filter is the safe path and must not be flagged"
        )


# ---------------------------------------------------------------------------
# LC-HARDEN-TAINT-PROMPTLOAD-001  (taint): request -> load_prompt() path
# ---------------------------------------------------------------------------
class TestPromptLoadTraversal:
    def test_request_input_into_load_prompt_flagged(self, tmp_path):
        # A concrete request source reaches the load_prompt() path.
        src = (
            "PROMPT_DIR = './prompt_library/'\n"
            "def load_named_prompt():\n"
            "    prompt_name = request.args.get('name')\n"
            "    path = PROMPT_DIR + prompt_name\n"
            "    return load_prompt(path)\n"
        )
        findings = _scan(
            tmp_path, "promptload_pos.py", src, TAINT_RULES, "LC-HARDEN-TAINT-PROMPTLOAD-001"
        )
        assert findings, "an untrusted param into load_prompt() as a path must be flagged"

    def test_plain_library_parameter_is_not_assumed_untrusted(self, tmp_path):
        src = "def load_configured_prompt(prompt_path):\n    return load_prompt(prompt_path)\n"
        findings = _scan(
            tmp_path,
            "promptload_library_api.py",
            src,
            TAINT_RULES,
            "LC-HARDEN-TAINT-PROMPTLOAD-001",
        )
        assert findings == []

    def test_constant_load_prompt_not_flagged(self, tmp_path):
        # Hardcoded constant path: no untrusted source reaches load_prompt.
        src = "def load_default():\n    return load_prompt('./prompt_library/answer.yaml')\n"
        findings = _scan(
            tmp_path, "promptload_neg.py", src, TAINT_RULES, "LC-HARDEN-TAINT-PROMPTLOAD-001"
        )
        assert findings == [], (
            "load_prompt() on a hardcoded constant path is the safe path and must not be flagged"
        )


# ---------------------------------------------------------------------------
# LC-HARDEN-TAINT-CYPHER-001  (taint): request -> GraphCypherQAChain.invoke
# ---------------------------------------------------------------------------
class TestCypherInjection:
    def test_param_into_cypher_chain_flagged(self, tmp_path):
        # Untrusted param reaches a GraphCypherQAChain that is then invoked.
        src = (
            "def answer_graph_question(question):\n"
            "    graph = Neo4jGraph(url='bolt://localhost:7687')\n"
            "    chain = GraphCypherQAChain.from_llm(LLM, graph=graph)\n"
            "    return chain.invoke({'query': question})\n"
        )
        findings = _scan(tmp_path, "cypher_pos.py", src, TAINT_RULES, "LC-HARDEN-TAINT-CYPHER-001")
        assert findings, "an untrusted param into a run GraphCypherQAChain must be flagged"

    def test_constant_cypher_chain_not_flagged(self, tmp_path):
        # Same chain, but the question is a hardcoded constant: no user input.
        src = (
            "def scheduled_report():\n"
            "    graph = Neo4jGraph(url='bolt://localhost:7687')\n"
            "    chain = GraphCypherQAChain.from_llm(LLM, graph=graph)\n"
            "    return chain.invoke({'query': 'how many nodes are in the graph'})\n"
        )
        findings = _scan(tmp_path, "cypher_neg.py", src, TAINT_RULES, "LC-HARDEN-TAINT-CYPHER-001")
        assert findings == [], (
            "a Cypher chain driven by a constant question has no untrusted source and must not be flagged"
        )


# ---------------------------------------------------------------------------
# LC-HARDEN-TAINT-JINJA-001  (taint): request -> jinja2 PromptTemplate.format
# ---------------------------------------------------------------------------
class TestJinjaSSTI:
    def test_param_into_jinja_format_flagged(self, tmp_path):
        # Untrusted param rendered by a jinja2-format PromptTemplate.
        src = (
            "def build_answer_prompt(user_question):\n"
            "    prompt = PromptTemplate(\n"
            "        input_variables=['question'],\n"
            "        template='{{ question }}',\n"
            "        template_format='jinja2',\n"
            "    )\n"
            "    return prompt.format(question=user_question)\n"
        )
        findings = _scan(
            tmp_path, "jinjataint_pos.py", src, TAINT_RULES, "LC-HARDEN-TAINT-JINJA-001"
        )
        assert findings, "an untrusted param rendered by a jinja2 PromptTemplate must be flagged"

    def test_param_into_default_format_not_flagged(self, tmp_path):
        # Same flow, but the default (f-string) template_format: the sink's
        # pattern-inside requires template_format='jinja2', so it must not fire.
        src = (
            "def build_answer_prompt(user_question):\n"
            "    prompt = PromptTemplate(\n"
            "        input_variables=['question'],\n"
            "        template='{question}',\n"
            "    )\n"
            "    return prompt.format(question=user_question)\n"
        )
        findings = _scan(
            tmp_path, "jinjataint_neg.py", src, TAINT_RULES, "LC-HARDEN-TAINT-JINJA-001"
        )
        assert findings == [], (
            "a param into a default (f-string) PromptTemplate is not SSTI and must not be flagged"
        )


# ---------------------------------------------------------------------------
# #53 review probes for the search-mode rules
# ---------------------------------------------------------------------------
class TestReviewProbes53:
    @pytest.mark.parametrize(
        "call",
        [
            "store.similarity_search_with_score(q, filter=user_filter)",
            "store.max_marginal_relevance_search(q, filter=user_filter)",
            "store.similarity_search_by_vector(v, filter=user_filter)",
        ],
    )
    def test_vector_filter_sibling_methods_flagged(self, tmp_path, call):
        src = f"def search(store, q, v, user_filter):\n    return {call}\n"
        assert _scan(tmp_path, "vf.py", src, SEARCH_RULES, "LC-HARDEN-VECTORFILTER-001")

    def test_vector_filter_none_not_flagged(self, tmp_path):
        src = "def search(store, q):\n    return store.similarity_search(q, filter=None)\n"
        assert _scan(tmp_path, "vf.py", src, SEARCH_RULES, "LC-HARDEN-VECTORFILTER-001") == []

    @pytest.mark.parametrize(
        "line",
        [
            "chain = GraphSparqlQAChain.from_llm(llm, graph=g, allow_dangerous_requests=True)",
            "chain = FalkorDBQAChain.from_llm(llm, graph=g, allow_dangerous_requests=True)",
            "chain = GraphCypherQAChain(llm=llm, graph=g, allow_dangerous_requests=True)",
        ],
    )
    def test_other_graph_chains_flagged(self, tmp_path, line):
        src = f"def build(llm, g):\n    {line}\n    return chain\n"
        assert _scan(tmp_path, "g.py", src, SEARCH_RULES, "LC-HARDEN-CYPHER-DANGEROUS-001")

    def test_requests_toolkit_is_not_a_graph_chain(self, tmp_path):
        src = "def build(w):\n    return RequestsToolkit(requests_wrapper=w, allow_dangerous_requests=True)\n"
        assert _scan(tmp_path, "g.py", src, SEARCH_RULES, "LC-HARDEN-CYPHER-DANGEROUS-001") == []
