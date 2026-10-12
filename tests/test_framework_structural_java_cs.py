"""Spring and ASP.NET framework rules as structural Opengrep rules (#53, #71).

The regex versions matched one token per line: any `.permitAll()`, any
`.AllowCredentials()`, any `UseDeveloperExceptionPage()` including the one
inside the default `if (env.IsDevelopment())` template. Requires the
Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _fires(tmp_path, filename, language, rule_id, src):
    (tmp_path / filename).write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [RULES / "framework_opengrep.yaml"], languages=[language])
    return any(f.rule_id == rule_id for f in findings)


def _java(body):
    return (
        "class SecurityConfig {\n"
        "    SecurityFilterChain chain(HttpSecurity http) throws Exception {\n"
        f"        {body}\n"
        "        return http.build();\n"
        "    }\n"
        "}\n"
    )


def _cs(body):
    return (
        "public class Startup {\n"
        "    public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {\n"
        f"        {body}\n"
        "    }\n"
        "}\n"
    )


JAVA_FIRES = [
    ("ns-fw-java-001", "http.csrf().disable();"),
    ("ns-fw-java-001", "http.csrf(AbstractHttpConfigurer::disable);"),
    ("ns-fw-java-001", "http.csrf(csrf -> csrf.disable());"),
    ("ns-fw-java-002", "http.authorizeHttpRequests(a -> a.anyRequest().permitAll());"),
    ("ns-fw-java-002", 'http.authorizeHttpRequests(a -> a.requestMatchers("/**").permitAll());'),
    ("ns-fw-java-002", 'http.authorizeRequests().antMatchers("/**").permitAll();'),
]
JAVA_QUIET = [
    ("ns-fw-java-001", "http.csrf(Customizer.withDefaults());"),
    ("ns-fw-java-002", 'http.authorizeHttpRequests(a -> a.requestMatchers("/login", "/css/**").permitAll());'),
    ("ns-fw-java-002", "http.authorizeHttpRequests(a -> a.anyRequest().authenticated());"),
]
CS_FIRES = [
    ("ns-fw-cs-002", "services.AddCors(o => o.AddPolicy(\"p\", b => b.AllowAnyOrigin().AllowCredentials()));"),
    ("ns-fw-cs-002", "services.AddCors(o => o.AddPolicy(\"p\", b => b.SetIsOriginAllowed(_ => true).AllowCredentials()));"),
    ("ns-fw-cs-005", "app.UseDeveloperExceptionPage();"),
]
CS_QUIET = [
    ("ns-fw-cs-002", "services.AddCors(o => o.AddPolicy(\"p\", b => b.WithOrigins(\"https://a.com\").AllowCredentials()));"),
    ("ns-fw-cs-005", "if (env.IsDevelopment()) { app.UseDeveloperExceptionPage(); }"),
]


@pytest.mark.parametrize("rule_id,body", JAVA_FIRES)
def test_java_fires(tmp_path, rule_id, body):
    assert _fires(tmp_path, "SecurityConfig.java", "java", rule_id, _java(body)), body


@pytest.mark.parametrize("rule_id,body", JAVA_QUIET)
def test_java_quiet(tmp_path, rule_id, body):
    assert not _fires(tmp_path, "SecurityConfig.java", "java", rule_id, _java(body)), body


@pytest.mark.parametrize("rule_id,body", CS_FIRES)
def test_cs_fires(tmp_path, rule_id, body):
    assert _fires(tmp_path, "Startup.cs", "csharp", rule_id, _cs(body)), body


@pytest.mark.parametrize("rule_id,body", CS_QUIET)
def test_cs_quiet(tmp_path, rule_id, body):
    assert not _fires(tmp_path, "Startup.cs", "csharp", rule_id, _cs(body)), body


def test_per_line_rules_are_removed():
    text = (RULES / "framework_rules.yaml").read_text(encoding="utf-8")
    for rid in ("ns-fw-java-001", "ns-fw-java-002", "ns-fw-java-004", "ns-fw-cs-001",
                "ns-fw-cs-002", "ns-fw-cs-004", "ns-fw-cs-005"):
        assert f"id: {rid}\n" not in text, rid
