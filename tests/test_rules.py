"""Tests for rule loading and NeuroScan rule matching."""

from pathlib import Path

import yaml

from rowan.core.findings import Category
from rowan.core.rules import NeuroScanRule, load_neuroscan_rules


def test_load_neuroscan_rules():
    rules_dir = Path(__file__).parent.parent / "rules"
    neuroscan_path = rules_dir / "neuroscan.yaml"

    if not neuroscan_path.exists():
        import pytest

        pytest.fail("rules/neuroscan.yaml not found")

    rules = load_neuroscan_rules(neuroscan_path)
    assert len(rules) > 0

    for rule in rules:
        assert isinstance(rule, NeuroScanRule)
        assert rule.metadata.id
        assert rule.metadata.severity.value in ("critical", "high", "medium", "low", "info")
        assert rule.metadata.category
        assert rule.patterns


def test_long_line_is_truncated_for_regex(tmp_path):
    """Over-long lines are truncated before regex matching (ReDoS input bound)."""
    rule_yaml = tmp_path / "rule.yaml"
    rule_yaml.write_text(
        "rules:\n"
        "  - id: NS-TEST-LONG\n"
        "    name: needle finder\n"
        "    severity: high\n"
        "    category: injection\n"
        "    cwe: [94]\n"
        "    languages: [python]\n"
        "    patterns:\n"
        "      - 'NEEDLE'\n"
        "    message: found needle\n"
    )
    rule = load_neuroscan_rules(rule_yaml)[0]

    # NEEDLE within the cap -> matches
    short = tmp_path / "short.py"
    short.write_text("x = '" + ("a" * 100) + "NEEDLE'")
    assert len(rule.check(short)) == 1

    # NEEDLE pushed past the 2000-char cap -> truncated away, no match
    long_file = tmp_path / "long.py"
    long_file.write_text("x = '" + ("a" * 3000) + "NEEDLE'")
    assert len(rule.check(long_file)) == 0


def test_rule_matches_vuln_pickle(tmp_path):
    """Test that NS-DESER-001 detects pickle.loads()."""
    file_path = tmp_path / "test.py"
    file_path.write_text("pickle.loads(data)")

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "neuroscan.yaml")
    deser_rules = [r for r in rules if r.metadata.id == "NS-DESER-001"]

    if not deser_rules:
        import pytest

        pytest.fail("NS-DESER-001 rule not found")

    findings = deser_rules[0].check(file_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "NS-DESER-001"
    assert findings[0].start_line == 1


def test_rule_skips_safe_torch(tmp_path):
    """Test that ns-aiml-030 does NOT flag weights_only=True."""
    file_path = tmp_path / "test.py"
    file_path.write_text('torch.load("model.pt", weights_only=True)')

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "ai_security.yaml")
    torch_rules = [r for r in rules if r.metadata.id == "ns-aiml-030"]

    if not torch_rules:
        import pytest

        pytest.fail("ns-aiml-030 rule not found")

    findings = torch_rules[0].check(file_path)
    assert len(findings) == 0


def test_rule_detects_eval(tmp_path):
    """Test that NS-INJECT-001 detects eval()."""
    file_path = tmp_path / "test.py"
    file_path.write_text("result = eval(user_input)")

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "neuroscan.yaml")
    eval_rules = [r for r in rules if r.metadata.id == "NS-INJECT-001"]

    if not eval_rules:
        import pytest

        pytest.fail("NS-INJECT-001 rule not found")

    findings = eval_rules[0].check(file_path)
    assert len(findings) >= 1
    assert any(f.rule_id == "NS-INJECT-001" for f in findings)


def test_language_rules_cover_multiline_and_concatenated_sinks(tmp_path):
    cases = [
        (
            "csharp.yaml",
            "CS-DESER-001",
            "case.cs",
            "var f = new BinaryFormatter();\nreturn f.Deserialize(stream);\n",
        ),
        (
            "ruby.yaml",
            "RB-INJECT-003",
            "case.rb",
            "@user = User.where(\"name = '#{params[:name]}'\").first\n",
        ),
        (
            "php.yaml",
            "PHP-INJECT-002",
            "case.php",
            "<?php shell_exec(\"convert \" . $_GET['file']);\n",
        ),
        (
            "go.yaml",
            "GO-INJECT-002",
            "case.go",
            'db.Query("SELECT * FROM users WHERE name = \'" + name + "\'")\n',
        ),
        ("java.yaml", "JA-PATH-001", "Case.java", 'File f = new File("/var/reports/" + name);\n'),
    ]
    rules_dir = Path(__file__).parent.parent / "rules"
    for rules_file, rule_id, filename, source in cases:
        target = tmp_path / filename
        target.write_text(source)
        rule = next(
            r for r in load_neuroscan_rules(rules_dir / rules_file) if r.metadata.id == rule_id
        )
        assert rule.check(target), f"{rule_id} did not match {source!r}"


def test_language_rule_expansions_keep_safe_forms_clean(tmp_path):
    cases = [
        (
            "csharp.yaml",
            "CS-DESER-001",
            "safe.cs",
            "return JsonSerializer.Deserialize<Foo>(stream);\n",
        ),
        (
            "ruby.yaml",
            "RB-INJECT-003",
            "safe.rb",
            '@user = User.where("name = ?", params[:name]).first\n',
        ),
        (
            "php.yaml",
            "PHP-INJECT-002",
            "safe.php",
            "<?php shell_exec(\"convert \" . escapeshellarg($_GET['file']));\n",
        ),
        (
            "go.yaml",
            "GO-INJECT-002",
            "safe.go",
            'db.Query("SELECT * FROM users WHERE name = ?", name)\n',
        ),
        ("java.yaml", "JA-PATH-001", "Safe.java", "File f = new File(baseDirectory, safeName);\n"),
    ]
    rules_dir = Path(__file__).parent.parent / "rules"
    for rules_file, rule_id, filename, source in cases:
        target = tmp_path / filename
        target.write_text(source)
        rule = next(
            r for r in load_neuroscan_rules(rules_dir / rules_file) if r.metadata.id == rule_id
        )
        assert not rule.check(target), f"{rule_id} false-positive on {source!r}"


def test_metadata_category_and_cwe_are_parsed(tmp_path):
    """Rules with category/cwe nested under metadata: are resolved correctly."""
    rules_yaml = {
        "rules": [
            {
                "id": "ns-test-001",
                "severity": "high",
                "patterns": ["test_pattern"],
                "metadata": {
                    "category": "prompt_injection",
                    "cwe": [94],
                },
            }
        ]
    }
    rules_file = tmp_path / "test_rules.yaml"
    rules_file.write_text(yaml.dump(rules_yaml))

    rules = load_neuroscan_rules(rules_file)
    assert len(rules) == 1
    rule = rules[0]
    assert rule.metadata.category == Category.PROMPT_INJECTION
    assert 94 in rule.metadata.cwe_ids


def test_top_level_category_and_cwe_win(tmp_path):
    """Top-level category/cwe override metadata: block."""
    rules_yaml = {
        "rules": [
            {
                "id": "ns-test-002",
                "severity": "medium",
                "category": "deserialization",
                "cwe": [502],
                "patterns": ["test_pattern"],
                "metadata": {
                    "category": "prompt_injection",
                    "cwe": [94],
                },
            }
        ]
    }
    rules_file = tmp_path / "test_rules.yaml"
    rules_file.write_text(yaml.dump(rules_yaml))

    rules = load_neuroscan_rules(rules_file)
    assert len(rules) == 1
    rule = rules[0]
    assert rule.metadata.category == Category.DESERIALIZATION
    assert rule.metadata.cwe_ids == [502]


def test_ns_auth_101_absorbs_ns_bb_002_hs256_rs256_pattern(tmp_path):
    """DEF-43: ns-bb-002 ("JWT algorithm confusion", misc_rules.yaml,
    CWE-327/crypto -- mis-classified, should be CWE-347/auth) and
    NS-AUTH-101 ("JWT verification with algorithm=none or signature
    verification disabled", security_surface.yaml, correct CWE-347/auth)
    both fired on the same `algorithms=[...none...]` idiom on the same
    line -- one issue reported twice. ns-bb-002 was deleted as the
    redundant rule, but it carried one genuinely-unique signal NS-AUTH-101 lacked: the
    `algorithm.*HS256.*RS256` algorithm-confusion pattern. That pattern was
    moved onto NS-AUTH-101 so deleting ns-bb-002 costs no recall."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "security_surface.yaml")
    rule = next(r for r in rules if r.metadata.id == "NS-AUTH-101")

    assert rule.metadata.cwe_ids == [347]
    assert rule.metadata.category == Category.AUTH

    confusion_file = tmp_path / "auth.py"
    confusion_file.write_text(
        "# verify with algorithm HS256 but token was signed RS256\n"
        "decoded = jwt.decode(token, public_key, algorithm=['HS256', 'RS256'])\n",
        encoding="utf-8",
    )
    assert rule.check(confusion_file), (
        "NS-AUTH-101 must catch the HS256/RS256 algorithm-confusion signal absorbed from ns-bb-002"
    )


def test_ns_ssti_rules_do_not_fire_on_bytestream_from_string(tmp_path):
    """NS-SSTI-001/NS-SSTI-102 ("Jinja2 template from string") used to fire
    on ByteStream.from_string(...) (a haystack byte-buffer factory with zero
    Jinja2 involvement) -- confirmed on a real repo scan: 33 of 87
    NS-SSTI-001 findings were exactly this.

    NOTE: this test exercises the legacy Python regex engine
    (NeuroScanRule.check(), matching what legacy_neuroscan=True runs). The
    default (Opengrep-converted) engine path has a separate, currently-open
    bug (GitHub issue #92) where pattern-not-regex silently doesn't exclude
    anything for rules whose only positive pattern is pattern-regex -- which
    is this rule's shape. This fix is real and correct at the rule-authoring
    level (and already effective for legacy_neuroscan=True users) but does
    NOT yet suppress the finding on the default path; that requires #92 to
    be fixed first. Don't mistake this test passing for the default-path
    behavor being fixed too -- it isn't yet.
    """
    rules_dir = Path(__file__).parent.parent / "rules"

    fp = tmp_path / "converters.py"
    fp.write_text(
        "source = ByteStream.from_string(json.dumps(data))\n",
        encoding="utf-8",
    )

    for rules_file, rule_id in [
        ("neuroscan.yaml", "NS-SSTI-001"),
        ("security_surface.yaml", "NS-SSTI-102"),
    ]:
        rules = load_neuroscan_rules(rules_dir / rules_file)
        rule = next(r for r in rules if r.metadata.id == rule_id)
        assert rule.check(fp) == [], (
            f"{rule_id} must not fire on ByteStream.from_string (no Jinja2 involvement)"
        )

    genuine = tmp_path / "prompt_builder.py"
    genuine.write_text(
        "compiled_template = self._env.from_string(message.text)\n",
        encoding="utf-8",
    )
    rules = load_neuroscan_rules(rules_dir / "neuroscan.yaml")
    rule = next(r for r in rules if r.metadata.id == "NS-SSTI-001")
    assert rule.check(genuine), (
        "NS-SSTI-001 must still catch a genuine Jinja2 Environment.from_string call"
    )


def test_ns_ssti_102_no_longer_duplicates_ns_ssti_001(tmp_path):
    """DEF-14: NS-SSTI-001 (neuroscan.yaml) and NS-SSTI-102
    (security_surface.yaml) both carried an identical `\\.from_string\\(`
    pattern (with matching exclusions), so every real Jinja2
    Environment.from_string() call was reported twice. Confirmed on a real
    repo scan (haystack): 100% of NS-SSTI-102's 55 findings were on the
    exact same (file, line) as an NS-SSTI-001 finding, and every one was
    this shared pattern -- none of NS-SSTI-102's other, genuinely unique
    patterns (render_template_string, bare Template(), jinja2.Template())
    ever fired. `\\.from_string\\(` was removed from NS-SSTI-102, which
    still reports the shared signal via NS-SSTI-001 alone, while its
    unique coverage is untouched."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "security_surface.yaml")
    rule = next(r for r in rules if r.metadata.id == "NS-SSTI-102")

    shared_pattern = tmp_path / "shared.py"
    shared_pattern.write_text(
        "compiled_template = self._env.from_string(message.text)\n",
        encoding="utf-8",
    )
    assert rule.check(shared_pattern) == [], (
        "NS-SSTI-102 must no longer duplicate NS-SSTI-001's .from_string( signal"
    )

    unique_render_template_string = tmp_path / "flask_view.py"
    unique_render_template_string.write_text(
        "return render_template_string(user_supplied_template)\n",
        encoding="utf-8",
    )
    assert rule.check(unique_render_template_string), (
        "NS-SSTI-102 must still catch render_template_string(), its own unique signal"
    )

    unique_bare_template = tmp_path / "bare_template.py"
    unique_bare_template.write_text(
        "t = jinja2.Template(user_supplied_template)\n",
        encoding="utf-8",
    )
    assert rule.check(unique_bare_template), (
        "NS-SSTI-102 must still catch jinja2.Template(), its own unique signal"
    )


def test_ns_sqli_004_ignores_java_executor_execute(tmp_path):
    """DEF-21: NS-SQLI-004's bare `\\.execute\\(` matched "execute" on ANY
    Java receiver, not just javax.sql.Statement. Confirmed on a real corpus
    scan (apache/dubbo): 100% of 167 fires were
    java.util.concurrent.Executor.execute(Runnable), the standard
    thread-pool task-submission idiom -- zero relation to JDBC/SQL. The
    bare pattern was removed; executeQuery/executeUpdate/createStatement
    (JDBC-specific method names) are unaffected."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "security_surface.yaml")
    rule = next(r for r in rules if r.metadata.id == "NS-SQLI-004")

    executor = tmp_path / "Pool.java"
    executor.write_text("executor.execute(() -> doWork());\n", encoding="utf-8")
    assert rule.check(executor) == [], "must not fire on Executor.execute(Runnable)"

    genuine = tmp_path / "Dao.java"
    genuine.write_text(
        'stmt.executeQuery("SELECT * FROM users WHERE id=" + id);\n', encoding="utf-8"
    )
    assert rule.check(genuine), "must still fire on Statement.executeQuery()"


def test_ns_sqli_005_catches_interpolated_sql_fstring(tmp_path):
    """NS-SQLI-005 (parity with Semgrep on ModelForge V08): catches SQL built
    in an f-string bound to a variable and executed elsewhere (e.g.
    `q = f"... ORDER BY {sort}"`), which NS-SQLI-001's execute-adjacent
    patterns miss. Precise: requires a SQL keyword AND a `{}` interpolation in
    the same f-string; parameterized queries and non-SQL f-strings don't fire,
    and direct execute() f-strings are left to NS-SQLI-001 (no double-fire)."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rule = next(
        r
        for r in load_neuroscan_rules(rules_dir / "neuroscan.yaml")
        if r.metadata.id == "NS-SQLI-005"
    )

    order_by = tmp_path / "search.py"
    order_by.write_text('    query = f"SELECT * FROM t ORDER BY {sort} DESC"\n', encoding="utf-8")
    assert rule.check(order_by), "must catch a SQL-keyword f-string with interpolation"

    parameterized = tmp_path / "safe.py"
    parameterized.write_text(
        'cur.execute(text("SELECT * FROM t WHERE id = :id"), {"id": 1})\n', encoding="utf-8"
    )
    assert rule.check(parameterized) == [], (
        "must not fire on a parameterized query with no interpolation"
    )

    non_sql = tmp_path / "log.py"
    non_sql.write_text('msg = f"loaded {count} rows for order {order_id}"\n', encoding="utf-8")
    assert rule.check(non_sql) == [], "must not fire on a non-SQL f-string that merely says 'order'"

    direct_execute = tmp_path / "direct.py"
    direct_execute.write_text(
        'cur.execute(f"SELECT * FROM t WHERE id = {uid}")\n', encoding="utf-8"
    )
    assert rule.check(direct_execute) == [], (
        "direct execute(f\"...\") is NS-SQLI-001's job, not this rule's"
    )


def test_ns_xss_005_catches_jinja_autoescape_false(tmp_path):
    """NS-XSS-005 (parity with Semgrep on ModelForge V19): flags a jinja2
    Environment created with autoescape=False (a stored-XSS sink), which our
    ruleset previously only saw via a miscategorized SSTI hit. Precise: only
    the explicit autoescape=False construction fires."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rule = next(
        r
        for r in load_neuroscan_rules(rules_dir / "neuroscan.yaml")
        if r.metadata.id == "NS-XSS-005"
    )

    unsafe = tmp_path / "reports.py"
    unsafe.write_text("_env = Environment(autoescape=False)\n", encoding="utf-8")
    findings = rule.check(unsafe)
    assert findings, "must fire on Environment(autoescape=False)"
    assert findings[0].category.value == "xss"

    safe = tmp_path / "safe.py"
    safe.write_text("_env = Environment(autoescape=True)\n", encoding="utf-8")
    assert rule.check(safe) == [], "must not fire on autoescape=True"


def test_cs_path_001_ignores_compound_identifier_substrings(tmp_path):
    """DEF-27: CS-PATH-001's `.*Request`/`.*User` matched those words as a
    SUBSTRING anywhere after the file API call, not as a standalone
    identifier. Confirmed on a real corpus scan (jellyfin): 3/5 fires
    were `UserConfigurationDirectoryPath` (an internal, hardcoded config
    path property) and `m.RequestUri` (System.Net.Http.HttpRequestMessage's
    property, used in test-mock HTTP responses) -- both unrelated
    compound identifiers that merely contain "User"/"Request" as a
    substring. `\\b` word boundaries now require a standalone token."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "csharp.yaml")
    rule = next(r for r in rules if r.metadata.id == "CS-PATH-001")

    config_path = tmp_path / "ImageController.cs"
    config_path.write_text(
        "var userDataPath = Path.Combine(paths.UserConfigurationDirectoryPath, name);\n",
        encoding="utf-8",
    )
    assert rule.check(config_path) == [], (
        "must not fire on UserConfigurationDirectoryPath (substring, not a standalone User reference)"
    )

    mock_request_uri = tmp_path / "HostTests.cs"
    mock_request_uri.write_text(
        'var content = File.OpenRead(Path.Combine("Test Data", m.RequestUri!.Host));\n',
        encoding="utf-8",
    )
    assert rule.check(mock_request_uri) == [], (
        "must not fire on HttpRequestMessage.RequestUri (substring, not a standalone Request reference)"
    )

    genuine = tmp_path / "FileController.cs"
    genuine.write_text(
        'var path = Path.Combine(root, Request.Query["file"]);\n',
        encoding="utf-8",
    )
    assert rule.check(genuine), "must still fire on a genuine standalone Request reference"


def test_ns_fw_java_003_ignores_bare_env_word(tmp_path):
    """DEF-22: ns-fw-java-003 ("Spring Actuator endpoints exposed") had
    bare `env\\b`/`heapdump\\b` as standalone patterns -- "env" is far too
    common a word/identifier to stand alone. Confirmed on a real corpus
    scan (apache/dubbo): 100% of 102 fires were unrelated uses of "env"
    (environment-support comments, ?env=gray canary-routing URL query
    params, YAML routing-rule snippets). Now scoped to require actual
    Spring Actuator config/path context."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "framework_rules.yaml")
    rule = next(r for r in rules if r.metadata.id == "ns-fw-java-003")

    canary_routing = tmp_path / "Router.java"
    canary_routing.write_text(
        'URL.valueOf("consumer://127.0.0.1/com.foo.BarService?env=gray&region=beijing");\n',
        encoding="utf-8",
    )
    assert rule.check(canary_routing) == [], "must not fire on Dubbo's ?env=gray canary routing"

    genuine = tmp_path / "application.properties"
    genuine.write_text("management.endpoints.web.exposure.include=env,heapdump\n", encoding="utf-8")
    assert rule.check(genuine), "must still fire on actual Actuator env/heapdump exposure"


def test_rb_inject_002_ignores_db_exec_member_call(tmp_path):
    """DEF-23: RB-INJECT-002's bare `\\bexec\\s*\\(` matched "exec" as a
    method name on ANY receiver, not just Ruby's Kernel#exec shell
    primitive. Confirmed on a real corpus scan (discourse): 100% of 617
    fires were DB.exec(sql)/builder.exec(...)/connection.exec("CREATE
    TABLE...") -- a SQL query wrapper's execute method, zero relation to
    shell execution. Genuine Kernel#exec is always called without an
    explicit receiver, so `(?<![.\\w])` (matching NS-INJECT-002's Python
    equivalent) excludes any `receiver.exec(...)` member call."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "ruby.yaml")
    rule = next(r for r in rules if r.metadata.id == "RB-INJECT-002")

    db_exec = tmp_path / "migration.rb"
    db_exec.write_text('DB.exec("CREATE TEMP TABLE verified_ids(val integer)")\n', encoding="utf-8")
    assert rule.check(db_exec) == [], "must not fire on DB.exec(), a SQL wrapper method"

    method_def = tmp_path / "runner.rb"
    method_def.write_text("def exec(*command, **exec_params)\n  command\nend\n", encoding="utf-8")
    assert rule.check(method_def) == [], "must not fire on a method definition named exec"

    genuine = tmp_path / "handler.rb"
    genuine.write_text('exec("rm -rf " + user_input)\n', encoding="utf-8")
    assert rule.check(genuine), "must still fire on genuine bare Kernel#exec shell execution"


def test_ns_xss_002_ignores_innerhtml_empty_string_clear(tmp_path):
    """DEF-26: NS-XSS-002 ("innerHTML / document.write DOM-based XSS
    sink") duplicated JS-XSS-001 (since deleted)
    on the shared `\\.innerHTML\\s*=` pattern (near-total overlap
    confirmed on two real corpus scans: discourse 91/93, prestashop
    77/78). JS-XSS-001's one useful addition was excluding
    `el.innerHTML = ''` (clearing content, not an XSS sink) -- confirmed
    25 combined real findings across both repos were exactly this.
    Merged into NS-XSS-002's pattern-not so deleting JS-XSS-001 loses
    no real detection."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "security_surface.yaml")
    rule = next(r for r in rules if r.metadata.id == "NS-XSS-002")

    cleared = tmp_path / "cleanup.js"
    cleared.write_text("el.innerHTML = '';\n", encoding="utf-8")
    assert rule.check(cleared) == [], "must not fire on el.innerHTML = '' (clearing content)"

    genuine = tmp_path / "render.js"
    genuine.write_text("el.innerHTML = userComment;\n", encoding="utf-8")
    assert rule.check(genuine), "must still fire on a genuine innerHTML XSS sink"


def test_ns_fw_js_003_ignores_non_express_post_put(tmp_path):
    """DEF-25: ns-fw-js-003 ("Express missing CSRF protection") had bare
    `\\.post\\(`/`\\.put\\(` patterns matching the method name on ANY
    receiver. Confirmed on two real corpus scans: discourse (225 fires)
    were pretender.js mock-server test route definitions
    (`pretender.post(...)`/`server.put(...)`, Ember.js frontend test
    fixtures, not real server routes); prestashop (72 fires) were
    jQuery's client-side AJAX helper (`$.post(...)`) -- the client making
    a request, the opposite of a server handling one without CSRF
    protection. Scoped to the standard Express convention
    (`app.post(...)`/`router.post(...)`)."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "framework_rules.yaml")
    rule = next(r for r in rules if r.metadata.id == "ns-fw-js-003")

    mock_server = tmp_path / "mock.js"
    mock_server.write_text('pretender.post("/admin/email/test", () => {});\n', encoding="utf-8")
    assert rule.check(mock_server) == [], "must not fire on pretender.js mock-server test routes"

    jquery_ajax = tmp_path / "client.js"
    jquery_ajax.write_text(
        "$.post(url).then(() => window.location.assign(redirectUrl));\n", encoding="utf-8"
    )
    assert rule.check(jquery_ajax) == [], "must not fire on jQuery's client-side $.post()"

    genuine = tmp_path / "server.js"
    genuine.write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.post('/transfer', (req, res) => { doTransfer(req.body); });\n",
        encoding="utf-8",
    )
    assert rule.check(genuine), "must still fire on a real Express app.post() route without CSRF"


def test_ns_path_005_ignores_unrelated_extract_methods(tmp_path):
    """DEF-16: NS-PATH-005's bare `\\.extract\\(` pattern matched the method
    name "extract" on ANY receiver, not just tarfile/zipfile objects.
    Confirmed on a real corpus scan: the majority of this rule's fires were
    OpenTelemetry's propagator.extract(carrier), BeautifulSoup's
    tag.extract(), and unrelated tool APIs (tavily_client.extract(...),
    trafilatura.extract(...)) -- none archive-related. The bare pattern
    was removed; `\\.extractall\\(` remains the archive-extraction signal."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "security_surface.yaml")
    rule = next(r for r in rules if r.metadata.id == "NS-PATH-005")

    otel = tmp_path / "otel.py"
    otel.write_text(
        "span_context = self.propagator.extract(carrier=self.carrier)\n", encoding="utf-8"
    )
    assert rule.check(otel) == [], "must not fire on OpenTelemetry's propagator.extract()"

    bs4 = tmp_path / "bs4_cleanup.py"
    bs4.write_text("[tag.extract() for tag in soup.find_all(undesired_tag)]\n", encoding="utf-8")
    assert rule.check(bs4) == [], "must not fire on BeautifulSoup's tag.extract()"

    genuine = tmp_path / "archive.py"
    genuine.write_text("archive.extractall(dest_dir)\n", encoding="utf-8")
    assert rule.check(genuine), "must still fire on a genuine archive.extractall() call"

    safe_tar = tmp_path / "safe_archive.py"
    safe_tar.write_text(
        'with tarfile.open(fileobj=data, mode="r:gz") as archive:\n'
        '    archive.extractall(destination, filter="data")\n',
        encoding="utf-8",
    )
    assert rule.check(safe_tar) == [], "safe filtered extraction must not fire"


def test_ns_deser_001_catches_cpickle_and_underscore_pickle(tmp_path):
    """DEF-17: NS-DESER-001 only matched `pickle\\.loads?\\(`/`dill\\.loads?\\(`;
    ns-aiml-034 (a near-duplicate, now disabled -- see thresholds.yaml) also
    caught `cPickle\\.loads?\\(`/`_pickle\\.loads?\\(` (Python 2 / internal
    pickle module aliases, equally dangerous). Merged into NS-DESER-001 so
    disabling ns-aiml-034 doesn't lose that coverage."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "neuroscan.yaml")
    rule = next(r for r in rules if r.metadata.id == "NS-DESER-001")

    cpickle = tmp_path / "legacy.py"
    cpickle.write_text("obj = cPickle.loads(data)\n", encoding="utf-8")
    assert rule.check(cpickle), "must catch cPickle.loads(), merged from ns-aiml-034"

    underscore_pickle = tmp_path / "internal.py"
    underscore_pickle.write_text("obj = _pickle.loads(data)\n", encoding="utf-8")
    assert rule.check(underscore_pickle), "must catch _pickle.loads(), merged from ns-aiml-034"


def test_ns_crypto_102_scoped_to_js_ts_only(tmp_path):
    """DEF-18: NS-CRYPTO-102's Python hashlib.md5(...)/hashlib.sha1(...)
    patterns duplicated NS-CRYPTO-001 (MD5, severity medium) and
    NS-CRYPTO-002 (SHA-1, severity low) exactly, at a single uniform
    WARNING severity that lost the MD5-is-worse-than-SHA-1 distinction.
    Confirmed on a corpus scan: 38/39 fires were Python (pure duplicates),
    only 1 was the genuine JS/TS crypto.createHash(...) signal this rule
    now scopes to exclusively."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "security_surface.yaml")
    rule = next(r for r in rules if r.metadata.id == "NS-CRYPTO-102")

    py_md5 = tmp_path / "hasher.py"
    py_md5.write_text("h = hashlib.md5(data)\n", encoding="utf-8")
    assert rule.check(py_md5) == [], (
        "must no longer duplicate NS-CRYPTO-001's Python hashlib.md5() coverage"
    )

    js_md5 = tmp_path / "hasher.js"
    js_md5.write_text("const h = crypto.createHash('md5');\n", encoding="utf-8")
    assert rule.check(js_md5), (
        "must still catch JS/TS crypto.createHash('md5'), its own unique signal"
    )


def test_rs_config_001_respects_comment_and_test_path_exclusions(tmp_path):
    """RS-CONFIG-001 ("unwrap() in production code") used to have two dead
    exclusions: `pattern-not: 'tests/'` checked the matched LINE's content
    for the literal substring "tests/" (never true for a real .unwrap() call
    in a test file), and `pattern-not: (?m)^\\s*#` used Python's comment
    character instead of Rust's `//` -- confirmed on a real repo scan
    (vllm): 128 of 607 findings were in files genuinely under a tests/
    directory, none excluded. Fixed via exclude_paths (file-path-based, the
    correct mechanism) and the real Rust comment prefix."""
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "rust.yaml")
    rule = next(r for r in rules if r.metadata.id == "RS-CONFIG-001")

    commented = tmp_path / "lib.rs"
    commented.write_text(
        "// let x = risky.unwrap();\nlet y = safe_value;\n",
        encoding="utf-8",
    )
    assert rule.check(commented) == [], "must not fire on a real Rust ('//') comment"

    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    test_file = test_dir / "chat.rs"
    test_file.write_text("let x = risky.unwrap();\n", encoding="utf-8")
    assert rule.check(test_file) == [], "must not fire on a file under a tests/ directory"

    genuine = tmp_path / "src" / "lib.rs"
    genuine.parent.mkdir()
    genuine.write_text("let x = risky.unwrap();\n", encoding="utf-8")
    assert rule.check(genuine), "must still fire on a genuine production unwrap()"


def test_c_family_rules_use_correct_comment_syntax(tmp_path):
    """go.yaml/java.yaml/csharp.yaml/javascript.yaml (and rust.yaml, covered
    separately) all used Python's '#' comment marker in pattern-not instead
    of the C-family '//' these languages actually use, so a commented-out
    dangerous line was never excluded on any of them. One representative
    rule per language, each with its real vulnerable pattern commented out
    with '//', plus the same pattern uncommented to confirm it still fires."""
    rules_dir = Path(__file__).parent.parent / "rules"
    cases = [
        ("go.yaml", "GO-INJECT-001", "main.go", 'exec.Command("sh", "-c", userInput)'),
        ("java.yaml", "JA-INJECT-001", "Handler.java", "Runtime.getRuntime().exec(userInput);"),
        ("csharp.yaml", "CS-INJECT-001", "Handler.cs", "Process.Start(userInput);"),
        ("javascript.yaml", "JS-INJECT-001", "handler.js", "eval(userInput)"),
    ]
    for fname, rule_id, filename, dangerous_line in cases:
        rules = load_neuroscan_rules(rules_dir / fname)
        rule = next(r for r in rules if r.metadata.id == rule_id)

        commented = tmp_path / f"commented_{filename}"
        commented.write_text(f"// {dangerous_line}\n", encoding="utf-8")
        assert rule.check(commented) == [], (
            f"{rule_id} must not fire on a real {fname.split('.')[0]} ('//') comment"
        )

        genuine = tmp_path / f"genuine_{filename}"
        genuine.write_text(f"{dangerous_line}\n", encoding="utf-8")
        assert rule.check(genuine), f"{rule_id} must still fire on an uncommented match"


def test_ns_aiml_030_detects_numpy_load_library(tmp_path):
    """NS-AIML-030 detects numpy.ctypeslib.load_library()."""
    file_path = tmp_path / "loader.py"
    file_path.write_text("lib = numpy.ctypeslib.load_library(name, path)\n")

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "ai_ml_neuroscan.yaml")
    matches = [r for r in rules if r.metadata.id == "NS-AIML-030"]
    assert matches, "NS-AIML-030 rule not found"
    assert len(matches[0].check(file_path)) == 1


def test_ns_aiml_031_detects_f2py_compile(tmp_path):
    """NS-AIML-031 detects numpy.f2py.compile()."""
    file_path = tmp_path / "build.py"
    file_path.write_text("numpy.f2py.compile(source, modulename='m')\n")

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "ai_ml_neuroscan.yaml")
    matches = [r for r in rules if r.metadata.id == "NS-AIML-031"]
    assert matches, "NS-AIML-031 rule not found"
    assert len(matches[0].check(file_path)) == 1


def test_ns_aiml_032_detects_onnx_custom_ops_library(tmp_path):
    """NS-AIML-032 detects SessionOptions.register_custom_ops_library()."""
    file_path = tmp_path / "session.py"
    file_path.write_text("opts.register_custom_ops_library(so_path)\n")

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "ai_ml_neuroscan.yaml")
    matches = [r for r in rules if r.metadata.id == "NS-AIML-032"]
    assert matches, "NS-AIML-032 rule not found"
    assert len(matches[0].check(file_path)) == 1


def test_ns_sec_001_detects_hardcoded_aws_key(tmp_path):
    """ns-sec-001 detects a literal AWS access key ID in a workflow file."""
    file_path = tmp_path / "deploy.yml"
    file_path.write_text('        AWS_ACCESS_KEY_ID: "AKIAABCDEFGHIJKLMNOP"\n')

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-sec-001"]
    assert matches, "ns-sec-001 rule not found"
    assert len(matches[0].check(file_path)) == 1


def test_ns_sec_001_ignores_documented_example_key_and_real_secret_ref(tmp_path):
    """ns-sec-001 must not flag AWS's own docs example key or a proper secrets ref."""
    file_path = tmp_path / "deploy.yml"
    file_path.write_text(
        "        # example: AKIAIOSFODNN7EXAMPLE\n"
        "        AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n"
    )

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-sec-001"]
    assert matches, "ns-sec-001 rule not found"
    assert len(matches[0].check(file_path)) == 0


def test_ns_cicd_001_detects_pull_request_target(tmp_path):
    """ns-cicd-001 detects the pull_request_target trigger."""
    file_path = tmp_path / "ci.yml"
    file_path.write_text("on:\n  pull_request_target:\n    types: [opened]\n")

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-001"]
    assert matches, "ns-cicd-001 rule not found"
    assert len(matches[0].check(file_path)) == 1


def test_ns_cicd_001_ignores_plain_pull_request(tmp_path):
    """ns-cicd-001 must not fire on the safe pull_request trigger."""
    file_path = tmp_path / "ci.yml"
    file_path.write_text("on:\n  pull_request:\n    types: [opened]\n")

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-001"]
    assert matches, "ns-cicd-001 rule not found"
    assert len(matches[0].check(file_path)) == 0


def test_ns_cicd_002_detects_unpinned_action(tmp_path):
    """ns-cicd-002 detects a third-party action pinned to a floating branch."""
    file_path = tmp_path / "ci.yml"
    file_path.write_text("      - uses: some-org/some-action@main\n")

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-002"]
    assert matches, "ns-cicd-002 rule not found"
    assert len(matches[0].check(file_path)) == 1


def test_ns_cicd_002_ignores_sha_pinned_action(tmp_path):
    """ns-cicd-002 must not fire when the action is pinned to a full commit SHA."""
    file_path = tmp_path / "ci.yml"
    file_path.write_text(
        "      - uses: some-org/some-action@8f4b7f84864484a7bf31766abe9204da3cbe65b3\n"
    )

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-002"]
    assert matches, "ns-cicd-002 rule not found"
    assert len(matches[0].check(file_path)) == 0


def test_ns_cicd_003_detects_untrusted_context_expression(tmp_path):
    """ns-cicd-003 detects an untrusted PR title interpolated into the workflow."""
    file_path = tmp_path / "ci.yml"
    file_path.write_text('      - run: echo "${{ github.event.pull_request.title }}"\n')

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-003"]
    assert matches, "ns-cicd-003 rule not found"
    assert len(matches[0].check(file_path)) == 1


def test_ns_cicd_003_detects_block_form_shell_assignment(tmp_path):
    """Block-form `run: |` puts the expression on its own line, as a shell assignment."""
    file_path = tmp_path / "ci.yml"
    file_path.write_text(
        "      - run: |\n"
        '          TITLE="${{ github.event.pull_request.title }}"\n'
        '          echo "$TITLE"\n'
    )

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-003"]
    assert matches, "ns-cicd-003 rule not found"
    assert len(matches[0].check(file_path)) == 1


def test_ns_cicd_003_ignores_non_shell_yaml_context(tmp_path):
    """The same expression in `with:`, `env:`, or `if:` is data, not shell source."""
    file_path = tmp_path / "ci.yml"
    file_path.write_text(
        "        if: contains(github.event.pull_request.title, 'x')\n"
        "        env:\n"
        "          TITLE: ${{ github.event.pull_request.title }}\n"
        "        with:\n"
        "          title: ${{ github.event.pull_request.title }}\n"
    )

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-003"]
    assert matches, "ns-cicd-003 rule not found"
    assert matches[0].check(file_path) == []


def _misc_rule(rule_id: str):
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "misc_rules.yaml")
    matches = [r for r in rules if r.metadata.id == rule_id]
    assert matches, f"{rule_id} rule not found"
    return matches[0]


def test_ns_bb_017_detects_container_with_no_isolation(tmp_path):
    """A container created with no isolation option at all is flagged."""
    file_path = tmp_path / "executor.py"
    file_path.write_text(
        "c = client.containers.create(\n"
        '    "python:3-slim",\n'
        "    tty=True,\n"
        "    detach=True,\n"
        '    volumes={"/host/work": {"bind": "/workspace", "mode": "rw"}},\n'
        ")\n"
    )
    assert len(_misc_rule("ns-bb-017").check(file_path)) == 1


def test_ns_bb_017_detects_call_passed_as_reference(tmp_path):
    """The call is often handed to asyncio.to_thread, so there is no `(`.

    Regression test: the first version of this rule required an opening paren
    and therefore missed `await asyncio.to_thread(client.containers.create, ...)`,
    which is exactly how AutoGen's Docker executor creates its container.
    """
    file_path = tmp_path / "executor.py"
    file_path.write_text(
        "container = await asyncio.to_thread(\n"
        "    client.containers.create,\n"
        "    self._image,\n"
        "    detach=True,\n"
        ")\n"
    )
    assert len(_misc_rule("ns-bb-017").check(file_path)) == 1


def test_ns_bb_017_suppressed_by_any_isolation_option(tmp_path):
    """One isolation option in the window means the author considered them."""
    file_path = tmp_path / "executor.py"
    file_path.write_text(
        "c = client.containers.create(\n"
        '    "python:3-slim",\n'
        '    network_mode="none",\n'
        '    user="1000:1000",\n'
        '    cap_drop=["ALL"],\n'
        ")\n"
    )
    assert _misc_rule("ns-bb-017").check(file_path) == []


def test_ns_bb_017_suppressed_by_kwargs_splat(tmp_path):
    """Caller-supplied **kwargs put the isolation config out of reach.

    Deciding this call site is impossible, so the rule stays quiet rather than
    guessing. Verified against dagster and prefect, which both build container
    options into a dict and splat it.
    """
    file_path = tmp_path / "launcher.py"
    file_path.write_text(
        "c = client.containers.create(\n    image,\n    detach=True,\n    **container_kwargs,\n)\n"
    )
    assert _misc_rule("ns-bb-017").check(file_path) == []


def test_ns_bb_017_unrelated_splat_does_not_suppress(tmp_path):
    """Only a *kwargs-shaped splat suppresses; **extra_volumes must not.

    AutoGen's real call splats `**self._extra_volumes` inside the volumes dict
    while setting no isolation option, and must still be reported.
    """
    file_path = tmp_path / "executor.py"
    file_path.write_text(
        "c = client.containers.create(\n"
        "    image,\n"
        '    volumes={"/w": {"bind": "/workspace", "mode": "rw"}, **self._extra_volumes},\n'
        ")\n"
    )
    assert len(_misc_rule("ns-bb-017").check(file_path)) == 1


def test_ns_cicd_004_detects_workflow_input_in_run_script(tmp_path):
    """ns-cicd-004 detects a workflow_dispatch input pasted into a run: script."""
    file_path = tmp_path / "ci.yml"
    file_path.write_text(
        "      - run: git show-ref --verify refs/tags/${{ github.event.inputs.ref }}\n"
    )

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-004"]
    assert matches, "ns-cicd-004 rule not found"
    assert len(matches[0].check(file_path)) == 1


def test_ns_cicd_004_detects_short_inputs_form(tmp_path):
    """The `inputs.x` shorthand is equivalent to `github.event.inputs.x`."""
    file_path = tmp_path / "ci.yml"
    file_path.write_text('      - run: ./build.sh "${{ inputs.version }}"\n')

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-004"]
    assert len(matches[0].check(file_path)) == 1


def test_ns_cicd_004_does_not_treat_run_name_as_shell(tmp_path):
    file_path = tmp_path / "ci.yml"
    file_path.write_text('run-name: "Build ${{ inputs.package }}"\n', encoding="utf-8")

    rules_dir = Path(__file__).parent.parent / "rules"
    rule = next(
        r
        for r in load_neuroscan_rules(rules_dir / "github_actions.yaml")
        if r.metadata.id == "ns-cicd-004"
    )
    assert rule.check(file_path) == []


def test_ns_cicd_004_detects_input_inside_multiline_run_block(tmp_path):
    """The `run: |` block form is the common one and the same-line pattern misses it.

    Measured on the corpus: 90 same-line instances against 295 inside block
    scalars, so matching only the same line saw under a quarter of them.
    """
    file_path = tmp_path / "ci.yml"
    file_path.write_text(
        "      - name: Determine release tag\n"
        "        run: |\n"
        '          if [ -n "${{ inputs.release_tag }}" ]; then\n'
        '            echo "tag=${{ inputs.release_tag }}" >> $GITHUB_OUTPUT\n'
        "          fi\n"
    )
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-004"]
    assert len(matches[0].check(file_path)) == 2


def test_ns_cicd_004_block_form_needs_a_shell_construct(tmp_path):
    """A bare YAML value is not shell text, even indented under a step.

    This is what keeps `run-name:`, `group:` and docker metadata `type=raw`
    values from firing: the line carries an interpolation but no shell.
    """
    file_path = tmp_path / "ci.yml"
    file_path.write_text(
        '    run-name: "Integration tests - ${{ inputs.working_directory }}"\n'
        "    concurrency:\n"
        "      group: build-${{ inputs.hardware }}\n"
    )
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-004"]
    assert matches[0].check(file_path) == []


def test_ns_cicd_004_ignores_input_outside_run_script(tmp_path):
    """An input consumed by `with:` is data, not script text, and must not fire.

    This is the precision boundary of the rule: the same expression on a
    `with: ref:` line is how a workflow is *supposed* to pass an input.
    """
    file_path = tmp_path / "ci.yml"
    file_path.write_text(
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.inputs.ref }}\n"
        "      - name: Build ${{ inputs.package }}\n"
        "        env:\n"
        "          VERSION: ${{ inputs.version }}\n"
    )

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-004"]
    assert matches[0].check(file_path) == []


def test_ns_cicd_005_detects_fork_controlled_head_ref(tmp_path):
    """ns-cicd-005 detects a fork-chosen branch name pasted into a run: script."""
    file_path = tmp_path / "ci.yml"
    file_path.write_text("      - run: echo Building ${{ github.event.pull_request.head.ref }}\n")

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-005"]
    assert matches, "ns-cicd-005 rule not found"
    assert len(matches[0].check(file_path)) == 1


def test_ns_cicd_005_ignores_head_ref_outside_run_script(tmp_path):
    """`head.ref` passed through `with:` is the documented safe form."""
    file_path = tmp_path / "ci.yml"
    file_path.write_text(
        "        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n"
    )

    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "github_actions.yaml")
    matches = [r for r in rules if r.metadata.id == "ns-cicd-005"]
    assert matches[0].check(file_path) == []


def _surface_rule(rule_id: str):
    rules_dir = Path(__file__).parent.parent / "rules"
    rules = load_neuroscan_rules(rules_dir / "security_surface.yaml")
    matches = [r for r in rules if r.metadata.id == rule_id]
    assert matches, f"{rule_id} rule not found"
    return matches[0]


def test_ns_path_008_detects_format_into_url_path(tmp_path):
    """A path template filled by str.format with no encoding."""
    file_path = tmp_path / "tool.py"
    file_path.write_text("        path = self.server_params.path.format(**path_params)\n")
    assert len(_surface_rule("NS-PATH-008").check(file_path)) == 1


def test_ns_path_008_ignores_literal_template(tmp_path):
    """Formatting into a string literal with a generated value is not traversal.

    Regression: `\\s*` backtracked to zero width so the lookahead inspected the
    space rather than the quote, and `path = "/tmp/{}.wav".format(...)` matched.
    """
    file_path = tmp_path / "handler.py"
    file_path.write_text('        path = "/tmp/{}.wav".format(uuid.uuid4().hex)\n')
    assert _surface_rule("NS-PATH-008").check(file_path) == []


def test_ns_bb_018_detects_incumbent_identifier_in_conflict_error(tmp_path):
    """Naming the current holder of a contested resource hands out an identity."""
    file_path = tmp_path / "servicer.py"
    file_path.write_text(
        '            f"Agent type {request.type} already registered with '
        'client {existing_client_id}.",\n'
    )
    assert len(_misc_rule("ns-bb-018").check(file_path)) == 1


def test_ns_bb_018_ignores_non_principal_identifier(tmp_path):
    """`original_node_id` is a graph node, not someone who can be impersonated."""
    file_path = tmp_path / "fixer.py"
    file_path.write_text(
        '        msg = f"Skipped block for {original_node_id} - already a prerequisite"\n'
    )
    assert _misc_rule("ns-bb-018").check(file_path) == []


def test_ns_bb_018_ignores_server_side_log(tmp_path):
    """Logging the incumbent id is the recommended fix, not the defect."""
    file_path = tmp_path / "manager.py"
    file_path.write_text(
        "            logger.warning(\n"
        '                f"Graph already running on pod {current_owner_id}"\n'
        "            )\n"
    )
    assert _misc_rule("ns-bb-018").check(file_path) == []


def test_ns_bb_019_detects_identity_read_from_metadata(tmp_path):
    """gRPC metadata is caller-written, so an id read from it is asserted."""
    file_path = tmp_path / "servicer.py"
    file_path.write_text('    if (client_id := metadata.get("client-id")) is None:\n')
    assert len(_misc_rule("ns-bb-019").check(file_path)) == 1


def test_ns_bb_019_ignores_outbound_header_write(tmp_path):
    """Setting a header on an outbound client is the opposite of trusting one."""
    file_path = tmp_path / "client.py"
    file_path.write_text('        headers["x-tenant-id"] = langsmith_tenant_id\n')
    assert _misc_rule("ns-bb-019").check(file_path) == []


def test_ns_bb_019_ignores_snake_case_telemetry_metadata(tmp_path):
    """Tracing libraries carry an unrelated `metadata` dict keyed with snake_case."""
    file_path = tmp_path / "trace.py"
    file_path.write_text('        user = metadata.get("user_id")\n')
    assert _misc_rule("ns-bb-019").check(file_path) == []


def test_ns_proto_001_category_resolves_to_prototype_pollution():
    """NS-PROTO-001's declared category must be a valid Category member.

    Regression test: the rule previously declared 'prototype_pollution' before
    that value existed on the Category enum, so the ValueError fallback in
    load_neuroscan_rules silently miscategorized every finding as GENERAL.
    """
    rules_path = Path(__file__).resolve().parents[1] / "rules" / "security_surface.yaml"
    rules = load_neuroscan_rules(rules_path)
    proto_rules = [r for r in rules if r.metadata.id == "NS-PROTO-001"]
    assert proto_rules, "NS-PROTO-001 rule not found"
    assert proto_rules[0].metadata.category == Category.PROTOTYPE_POLLUTION
    assert proto_rules[0].metadata.category != Category.GENERAL


# ---------------------------------------------------------------------------
# python_web_surface.yaml: CWE-1004 / CWE-330 / CWE-276 (2026-08-02)
#
# Each rule ships with a positive AND a negative case per CONTRIBUTING.md
# ("Write the negative case too"). Real-world validation hit counts live in
# each rule's own engine note in rules/python_web_surface.yaml.
# ---------------------------------------------------------------------------


def _web_surface_rule(rule_id: str) -> NeuroScanRule:
    rules_path = Path(__file__).resolve().parents[1] / "rules" / "python_web_surface.yaml"
    rules = load_neuroscan_rules(rules_path)
    matches = [r for r in rules if r.metadata.id == rule_id]
    assert matches, f"{rule_id} not found in python_web_surface.yaml"
    return matches[0]


def test_ns_websec_1004_flags_cookie_without_httponly(tmp_path):
    rule = _web_surface_rule("ns-websec-1004-001")
    assert rule.metadata.cwe_ids == [1004]
    assert rule.metadata.category == Category.CONFIG

    path = tmp_path / "views.py"
    path.write_text(
        "def login(user):\n"
        "    resp = make_response(redirect('/'))\n"
        "    resp.set_cookie('session', issue_token(user.id))\n"
        "    return resp\n",
        encoding="utf-8",
    )
    findings = rule.check(path)
    assert len(findings) == 1
    assert findings[0].start_line == 3


def test_ns_websec_1004_silent_when_httponly_passed(tmp_path):
    """The sanitizer window must cover a multi-line set_cookie() call, and must
    accept a non-literal value: `httponly=settings.HTTPONLY` still passes the
    flag. Requiring the literal `True` produced 9 false positives in langflow."""
    rule = _web_surface_rule("ns-websec-1004-001")

    literal = tmp_path / "literal.py"
    literal.write_text(
        "def login(user):\n"
        "    resp = make_response(redirect('/'))\n"
        "    resp.set_cookie(\n"
        "        'session',\n"
        "        issue_token(user.id),\n"
        "        httponly=True,\n"
        "        secure=True,\n"
        "        samesite='Lax',\n"
        "    )\n"
        "    return resp\n",
        encoding="utf-8",
    )
    assert rule.check(literal) == []

    from_config = tmp_path / "from_config.py"
    from_config.write_text(
        "def login(user):\n"
        "    resp = make_response(redirect('/'))\n"
        "    resp.set_cookie(\n"
        "        'session',\n"
        "        issue_token(user.id),\n"
        "        httponly=auth_settings.ACCESS_HTTPONLY,\n"
        "    )\n"
        "    return resp\n",
        encoding="utf-8",
    )
    assert rule.check(from_config) == []


def test_ns_websec_330_flags_token_from_random_module(tmp_path):
    rule = _web_surface_rule("ns-websec-330-001")
    assert rule.metadata.cwe_ids == [330, 338]
    assert rule.metadata.category == Category.CRYPTO

    path = tmp_path / "security.py"
    path.write_text(
        "import random\n"
        "\n"
        "def new_reset_token() -> str:\n"
        "    reset_token = ''.join(random.choice('0123456789abcdef') for _ in range(16))\n"
        "    return reset_token\n"
        "\n"
        "def new_key() -> bytes:\n"
        "    key = bytes(random.getrandbits(8) for _ in range(32))\n"
        "    return key\n",
        encoding="utf-8",
    )
    lines = {f.start_line for f in rule.check(path)}
    assert lines == {4, 8}


def test_ns_websec_330_silent_on_secrets_and_systemrandom(tmp_path):
    rule = _web_surface_rule("ns-websec-330-001")
    path = tmp_path / "security.py"
    path.write_text(
        "import random\n"
        "import secrets\n"
        "\n"
        "_RNG = random.SystemRandom()\n"
        "\n"
        "def new_reset_token() -> str:\n"
        "    reset_token = secrets.token_urlsafe(32)\n"
        "    return reset_token\n"
        "\n"
        "def new_session_token() -> str:\n"
        "    session_token = ''.join(random.SystemRandom().choice('abcdef') for _ in range(8))\n"
        "    return session_token\n",
        encoding="utf-8",
    )
    assert rule.check(path) == []


def test_ns_websec_330_silent_on_benign_random_string(tmp_path):
    """The withdrawn idiom-anchored patterns fired on random suffixes for temp
    names (44 hits, near-100% false positive). Only a security-named binding
    counts."""
    rule = _web_surface_rule("ns-websec-330-001")
    path = tmp_path / "local.py"
    path.write_text(
        "import random\n"
        "import string\n"
        "\n"
        "def container_name(prefix: str) -> str:\n"
        "    suffix = ''.join(random.choice(string.ascii_lowercase) for _ in range(5))\n"
        "    return f'{prefix}-{suffix}'\n",
        encoding="utf-8",
    )
    assert rule.check(path) == []


def test_ns_websec_276_flags_world_writable_modes(tmp_path):
    rule = _web_surface_rule("ns-websec-276-001")
    assert rule.metadata.cwe_ids == [276, 732]
    assert rule.metadata.category == Category.CONFIG

    path = tmp_path / "configs.py"
    path.write_text(
        "import os\n"
        "\n"
        "def prepare(library_path, blob_path):\n"
        "    os.chmod(library_path, 0o777)\n"
        "    os.chmod(blob_path, 0o666)\n"
        "    os.umask(0)\n",
        encoding="utf-8",
    )
    lines = {f.start_line for f in rule.check(path)}
    assert lines == {4, 5, 6}


def test_ns_websec_276_silent_on_owner_only_modes(tmp_path):
    """World-*readable* is ordinary and correct; only the write bits count."""
    rule = _web_surface_rule("ns-websec-276-001")
    path = tmp_path / "configs.py"
    path.write_text(
        "import os\n"
        "\n"
        "def prepare(library_path, key_path, script_path):\n"
        "    os.chmod(library_path, 0o700)\n"
        "    os.chmod(key_path, 0o600)\n"
        "    os.chmod(script_path, 0o755)\n"
        "    os.umask(0o077)\n",
        encoding="utf-8",
    )
    assert rule.check(path) == []


def test_empty_rules_file_loads_as_no_rules(tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("# no rules yet\n", encoding="utf-8")
    assert load_neuroscan_rules(empty) == []

    not_a_mapping = tmp_path / "list.yaml"
    not_a_mapping.write_text("- a\n- b\n", encoding="utf-8")
    assert load_neuroscan_rules(not_a_mapping) == []


def test_taint_rule_files_yield_no_neuroscan_rules():
    """PL-15: `mode: taint` rules have no regex patterns and can never match."""
    from rowan.config import ScanConfig
    from rowan.core.rules import load_neuroscan_rules

    assert load_neuroscan_rules(ScanConfig.default_rules_dir() / "python_taint.yaml") == []
