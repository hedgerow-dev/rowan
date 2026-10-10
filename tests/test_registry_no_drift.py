"""Guards that keep the shared source/sink/sanitizer registry authoritative (issue #159).

The whole point of ``rowan/rules_registry.py`` is that a source/sink/
sanitizer list is defined once and can never silently diverge into a second,
drifted copy: the failure mode behind DEF-10/14/15/19/26 in ``BACKLOG.md``.
These tests are the enforcement:

* every ``# rowan-registry:begin ... end`` managed region in the rule YAML must
  already match what the registry renders (i.e. ``sync_registry.py`` is a no-op);
* the runtime sanitizer table must be exactly the registry's copy;
* a hand-copied web_request source block that forgot the sentinels fails CI.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

from rowan.core.findings import Category
from rowan.core.sanitizers import CATEGORY_SANITIZERS
from rowan.rules_registry import SANITIZER_REGEX, SOURCES

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"


def _load_sync_module():
    spec = importlib.util.spec_from_file_location(
        "rowan_sync_registry", PROJECT_ROOT / "scripts" / "sync_registry.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_all_managed_regions_in_sync():
    """`sync_registry.py --check` must pass: no region drifted from the registry."""
    sync = _load_sync_module()
    stale = [
        p.relative_to(PROJECT_ROOT)
        for p in sync.iter_rule_files()
        if not sync.sync_file(p, check=True)
    ]
    assert not stale, (
        f"registry-managed regions out of sync in {stale}; "
        "run: python scripts/sync_registry.py"
    )


def test_runtime_sanitizers_match_registry():
    """core.sanitizers must expose exactly the registry's regexes, per category."""
    expected = {c: list(p) for c, p in SANITIZER_REGEX.items()}
    assert expected == CATEGORY_SANITIZERS


def test_sanitizer_values_snapshot():
    """Behaviour lock: the sanitizer sets are unchanged from the pre-registry values.

    If this fails, a sanitizer set changed: that is a scan-behaviour change and
    must be intentional (update this snapshot and validate against the benchmark).
    """
    assert SANITIZER_REGEX[Category.COMMAND_INJECTION] == [
        r"shlex\.quote\(",
        r"shell\s*=\s*False",
        r"subprocess\.run\(\s*\[",
    ]
    assert SANITIZER_REGEX[Category.INJECTION] == [
        # Generalized from `cursor\.execute` to any DB handle (#302): the old
        # form recognized parameterized execution only on a receiver literally
        # named `cursor`, so conn/db/session.execute(sql, params) was reported
        # as "without parameterization". Benchmark re-validated after the
        # change; see the issue for the before/after.
        r"[\w.]+\.execute(?:many)?\(\s*(?:[rbuRBU]?\"[^\"]*\"|[rbuRBU]?'[^']*'|[A-Za-z_][\w.]*)\s*,",
        r"int\(",
        r"float\(",
        r"ast\.literal_eval\(",
        r"PreparedStatement",
        r"bindparam\(",
    ]
    # every category that had sanitizers before is still present
    assert {c.value for c in SANITIZER_REGEX} == {
        "injection", "command_injection", "path_traversal", "ssrf", "xss",
        "ssti", "deserialization", "nosql_injection", "prompt_injection", "general",
    }


# A block "is" the web_request source if its pattern-either lists both the first
# and last canonical patterns; the sentinel wraps exactly this shape.
_FIRST = SOURCES["web_request"][0]
# The last plain pattern; the FastAPI parameter entry after it is a mapping.
_LAST = [p for p in SOURCES["web_request"] if isinstance(p, str)][-1]
# user_input is web_request minus argv/env and ends on the same last pattern;
# web_request_argparse embeds the whole block. web_request_java / web_request_go
# are different languages and share no pattern with it.
_BEGIN_WEB_REQUEST = re.compile(
    r"#\s*rowan-registry:begin\s+source=(web_request|web_request_argparse|user_input)(?!\w)"
)


def test_no_hand_copied_web_request_block():
    """A full web_request block must live inside a sentinel, never hand-pasted.

    Counts canonical-block occurrences (identified by the last pattern,
    gr.UploadButton, which is unique to this fragment) and requires each to be
    covered by a `begin source=web_request` sentinel in the same file.
    """
    last_marker = f"- pattern: {_LAST}"
    for path in sorted(RULES_DIR.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        blocks = text.count(last_marker)
        sentinels = len(_BEGIN_WEB_REQUEST.findall(text))
        assert blocks == sentinels, (
            f"{path.name}: found {blocks} web_request block(s) but {sentinels} "
            "sentinel(s). A hand-copied block must be wrapped in "
            "'# rowan-registry:begin source=web_request' / end and expanded via "
            "scripts/sync_registry.py."
        )
        # sanity: the fragment's first pattern is present wherever the last is
        if blocks:
            assert f"- pattern: {_FIRST}" in text


def test_parameterized_query_sanitizer_matches_any_db_handle():
    """#302: the INJECTION sanitizer was `cursor\\.execute\\(...`, hardcoded to a
    receiver literally named `cursor`, while TNT-SQLI-002's sink patterns match
    any receiver ($DB/$CONN/$SESSION). A correctly parameterized query on any
    other handle was therefore reported as "without parameterization".

    Locks the behaviour rather than the spelling: real shapes that ARE
    parameterized must match, and shapes that only look parameterized must not.
    """
    import re

    pattern = next(
        p for p in SANITIZER_REGEX[Category.INJECTION] if "execute" in p
    )

    parameterized = [
        'conn.execute("INSERT INTO prefs (username) VALUES (?)", (username,))',
        # commas inside the SQL literal are the common case, not an edge case
        'conn.execute("INSERT INTO t (a, b) VALUES (?, ?)", (a, b))',
        "cursor.execute(sql, params)",
        'self.conn.execute("SELECT * FROM t WHERE id = ?", [tid])',
        'session.executemany("INSERT INTO t (a, b) VALUES (?, ?)", rows)',
    ]
    for src in parameterized:
        assert re.search(pattern, src), f"should read as parameterized: {src}"

    not_parameterized = [
        "cursor.execute(query)",
        'conn.execute(f"SELECT * FROM t WHERE x={user}")',
        # an f-string is NOT made safe by also passing params: interpolation
        # already happened, so this must stay flagged
        'conn.execute(f"SELECT * FROM t WHERE x={user}", (a,))',
        'conn.execute("SELECT " + user + " FROM t")',
    ]
    for src in not_parameterized:
        assert not re.search(pattern, src), f"must NOT read as parameterized: {src}"


def test_tnt_sqli_002_sanitizer_is_not_hardcoded_to_cursor():
    """The rule-level `pattern-sanitizers` had the same hardcoded-`cursor` bug
    as the registry regex above, independently (#302). Both had to be fixed;
    this pins the rule side."""
    import yaml

    rules_path = RULES_DIR / "python_taint_extended.yaml"
    data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    rule = next(r for r in data["rules"] if r["id"] == "TNT-SQLI-002")
    sanitizer_patterns = [
        p
        for block in rule["pattern-sanitizers"]
        for p in block["patterns"][0]["pattern-either"]
    ]
    execute_patterns = [p["pattern"] for p in sanitizer_patterns if "execute" in p["pattern"]]
    assert execute_patterns, "TNT-SQLI-002 must still recognize parameterized execution"
    for pat in execute_patterns:
        assert not pat.startswith("cursor."), (
            f"{pat!r} is hardcoded to a receiver named `cursor`; the sink patterns "
            "match any receiver, so the sanitizer must too"
        )
