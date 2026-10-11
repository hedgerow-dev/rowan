"""Regression tests for issue #270: `request.*` taint sources were classified
as function parameters, which floored SSRF/XSS/command-injection confidence.

`trace_source` looked up the *assignment* of a source snippet's root variable.
For `request.args.get("url")` the root variable is `request`, which is never
assigned in either major framework -- Flask imports it, Django passes it as a
view parameter -- so the lookup failed and returned ORIGIN_FUNCTION_PARAM
(0.3). `EnrichmentPass._apply_source_confidence` floors any finding whose
origin confidence is below its category threshold, and those thresholds are
0.5 for SSRF and 0.7 by default, so every request-sourced SSRF/XSS/cmdi flow
was reported at INFO with confidence 0.15 -- meaning the documented
`scan --severity high` CI gate passed textbook Flask SSRF.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from rowan.analysis.source_tracer import classify_origin
from rowan.config import ScanConfig
from rowan.pipeline import ScanPipeline

_FLASK_APP = '''\
import os
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url).text


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return os.system("ping -c 1 " + host)
'''

_DJANGO_VIEW = '''\
from django.utils.safestring import mark_safe


def profile(request):
    bio = request.GET.get("bio")
    return mark_safe(bio)
'''


class TestOriginClassification:
    def test_flask_request_is_http_input(self, tmp_path: Path) -> None:
        app = tmp_path / "app.py"
        app.write_text(_FLASK_APP, encoding="utf-8")
        assert classify_origin(str(app), 'request.args.get("url")', 10) == ("http_input", 1.0)

    def test_django_request_is_http_input(self, tmp_path: Path) -> None:
        """Django's `request` is a function parameter, which is precisely the
        shape the old root-variable trace mistook for an untraceable arg."""
        view = tmp_path / "views.py"
        view.write_text(_DJANGO_VIEW, encoding="utf-8")
        assert classify_origin(str(view), 'request.GET.get("bio")', 5) == ("http_input", 1.0)
        assert classify_origin(str(view), 'request.POST["x"]', 5) == ("http_input", 1.0)

    def test_non_http_origins_keep_their_classification(self, tmp_path: Path) -> None:
        app = tmp_path / "app.py"
        app.write_text(_FLASK_APP, encoding="utf-8")
        assert classify_origin(str(app), 'os.environ.get("HOME")', 10) == ("env_variable", 0.7)

    def test_bare_name_still_falls_back_to_tracing(self, tmp_path: Path) -> None:
        """A bare variable carries no information in itself, so the root
        variable trace (and its function_param fallback) must still run."""
        app = tmp_path / "app.py"
        app.write_text(_FLASK_APP, encoding="utf-8")
        assert classify_origin(str(app), "x", 10) == ("function_param", 0.3)

    def test_unparseable_snippet_is_not_classified(self, tmp_path: Path) -> None:
        """Taint snippets are frequently truncated; an unparseable one must
        fall through rather than raise."""
        app = tmp_path / "app.py"
        app.write_text(_FLASK_APP, encoding="utf-8")
        label, _ = classify_origin(str(app), 'requests.get(url', 10)
        assert label in (None, "function_param")


class TestEndToEndSeverity:
    def test_flask_ssrf_is_not_reported_as_info(self) -> None:
        # Deliberately NOT pytest's tmp_path: it is named after the test
        # function, and `is_test_path` tokenises the *absolute* path, so
        # every finding would be downgraded as test code and the severity
        # assertions below would pass or fail for the wrong reason. (That
        # absolute-path judgement is itself a defect -- any repo checked out
        # under a directory like "test-apps/" is silently downgraded -- but
        # it is out of scope here.)
        with tempfile.TemporaryDirectory(prefix="rowan-ssrf-") as td:
            target = Path(td)
            (target / "app.py").write_text(_FLASK_APP, encoding="utf-8")
            self._assert_ssrf_reported(ScanPipeline(ScanConfig(target=target, no_sca=True)).run())

    @staticmethod
    def _assert_ssrf_reported(result) -> None:

        flowed = [f for f in result.findings if f.taint_flow is not None]
        assert flowed, "the Flask app must produce taint findings"

        for f in flowed:
            assert f.metadata.get("source_origin") == "http_input", (
                f"{f.rule_id} classified its request source as "
                f"{f.metadata.get('source_origin')}"
            )
            assert not f.metadata.get("taint_unconfirmed"), f"{f.rule_id} was floored"

        ssrf = [f for f in flowed if f.category.value == "ssrf"]
        assert ssrf, "requests.get(user_url) must be reported as SSRF"
        assert all(f.severity.value != "info" for f in ssrf), (
            "Flask SSRF at INFO is what let `scan --severity high` pass it"
        )
        assert all(f.confidence > 0.5 for f in ssrf)


# Route parameters are request input with no request object in sight: FastAPI
# binds typed parameters, Flask binds `<name>` path variables. The taint rules
# treat them as sources; the tracer must too, or their flows are floored to
# INFO and hidden by --confirmed (#59).
_FASTAPI_APP = '''\
import subprocess
from fastapi import Depends, FastAPI
from unittest import mock

app = FastAPI()


def get_cmd():
    return "ls"


@app.get("/ping")
def ping(host: str):
    return subprocess.run("ping " + host, shell=True)


@app.get("/dep")
def dep(cmd: str = Depends(get_cmd)):
    return subprocess.run(cmd, shell=True)


def helper(host: str):
    return subprocess.run("ping " + host, shell=True)


@mock.patch("pkg.run")
def patched(host: str):
    return subprocess.run("ping " + host, shell=True)
'''

_FLASK_ROUTE_VAR = '''\
import os
from flask import Flask

app = Flask(__name__)


@app.route("/hi/<name>")
def hi(name):
    return os.system("echo " + name)
'''


class TestRouteParameterOrigin:
    def test_fastapi_route_parameter_is_http_input(self, tmp_path: Path) -> None:
        app = tmp_path / "app.py"
        app.write_text(_FASTAPI_APP, encoding="utf-8")
        assert classify_origin(str(app), "host", 14) == ("http_input", 1.0)

    def test_flask_route_variable_is_http_input(self, tmp_path: Path) -> None:
        app = tmp_path / "app.py"
        app.write_text(_FLASK_ROUTE_VAR, encoding="utf-8")
        assert classify_origin(str(app), "name", 9) == ("http_input", 1.0)

    def test_dependency_and_non_route_parameters_stay_function_params(self, tmp_path: Path) -> None:
        app = tmp_path / "app.py"
        app.write_text(_FASTAPI_APP, encoding="utf-8")
        assert classify_origin(str(app), "cmd", 19) == ("function_param", 0.3)
        assert classify_origin(str(app), "host", 23) == ("function_param", 0.3)
        assert classify_origin(str(app), "host", 28) == ("function_param", 0.3)

    def test_fastapi_flow_is_confirmed_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rowan-route-") as td:
            target = Path(td)
            (target / "app.py").write_text(_FASTAPI_APP, encoding="utf-8")
            result = ScanPipeline(ScanConfig(target=target, no_sca=True)).run()
        ping = [f for f in result.findings if f.taint_flow is not None and f.start_line == 14]
        assert ping, "the FastAPI route flow must produce a taint finding"
        for f in ping:
            assert f.metadata.get("source_origin") == "http_input"
            assert not f.metadata.get("taint_unconfirmed")
            assert f.severity.value != "info"
