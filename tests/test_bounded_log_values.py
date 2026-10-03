"""Proof-based log forging calibration; schema/annotations never clear taint."""

import ast
from pathlib import Path

import pytest

from rowan.analysis.bounded_log_values import BoundedLogValues
from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext
from rowan.passes.enrichment import EnrichmentPass


@pytest.mark.parametrize(
    "body",
    [
        "n = int(raw)\nlogger.info('count=%s', n)",
        "n = float(raw)\nlogger.info(f'count={n:.2f}')",
        "n = len(raw)\nlogger.info(n)",
        "n = bool(raw)\nlogger.info(str(n))",
        "n = int(raw) + 2\nalias = n\nlogger.info(f'value={alias}')",
        "logging.info('value=%05d', raw)",
        "logging.log(20, 'value=%f', raw)",
        "n = int(raw)\nif condition:\n    n = float(raw)\nlogger.info(n)",
        "n = int(record.id)\nrecord.id = raw\nlogger.info('id=%s', n)",
    ],
)
def test_bounded_rendering(body):
    source = "import logging\ndef handler(raw, condition, record):\n" + "\n".join(
        "    " + s for s in body.splitlines()
    )
    path = Path("sample.py")
    safe = BoundedLogValues({path: ast.parse(source)}).safe_lines(path)
    assert len(safe) == 1


@pytest.mark.parametrize(
    "source",
    [
        "def handler(raw):\n    n: int = raw\n    logger.info(n)",
        "def handler(raw):\n    n = int(raw)\n    n = raw\n    logger.info(n)",
        "def handler(raw, int):\n    logger.info(int(raw))",
        "int = custom\ndef handler(raw):\n    logger.info(int(raw))",
        "from custom import int\ndef handler(raw):\n    logger.info(int(raw))",
        "from custom import *\ndef handler(raw):\n    logger.info(int(raw))",
        "def handler(raw):\n    n = int(raw)\n    if condition:\n        n = raw\n    logger.info(n)",
        "def handler(raw):\n    n = int(raw)\n    n += raw\n    logger.info(n)",
        "def handler(raw):\n    logger.info('%d %s', 2, raw)",
        "def handler(raw):\n    logger.info(raw, 2)",
        "def handler(raw):\n    logger.info('value=%s', raw)",
        "def handler(raw):\n    logger.info(f'{raw:d}')",
        "def handler(raw):\n    n = int(raw)\n    logger.info(f'{n:{raw}}')",
        "def handler(raw):\n    n = int(raw)\n    consume(n := raw)\n    logger.info(n)",
        "def handler(raw):\n    n = int(raw)\n    for x in values:\n        n = raw\n    logger.info(n)",
        "def handler(raw):\n    logger.info(int(raw)); logger.info(raw)",
        "def handler(record):\n    logger.info('%s', record.id)",
        "def handler(raw):\n    logger.info('value=%s', int(raw), extra={'value':raw})",
    ],
)
def test_unknown_or_mutated_values_retain_the_claim(source):
    path = Path("sample.py")
    assert not BoundedLogValues({path: ast.parse(source)}).safe_lines(path)


def test_imported_numeric_return_helper_and_shadowing(tmp_path):
    helper, caller = tmp_path / "helper.py", tmp_path / "handler.py"
    helper.write_text("def convert(value):\n    return int(value)\n")
    caller.write_text(
        'from helper import convert as coerce\ndef handler(raw):\n    n = coerce(raw)\n    logger.info("value=%s", n)\n'
    )
    trees = {p: ast.parse(p.read_text()) for p in (helper, caller)}
    assert BoundedLogValues(trees).safe_lines(caller) == {4}
    helper.write_text(helper.read_text() + "convert = custom\n")
    trees[helper] = ast.parse(helper.read_text())
    assert not BoundedLogValues(trees).safe_lines(caller)


def test_enrichment_only_removes_forging_not_sensitive_numeric_logging(tmp_path):
    path = tmp_path / "app.py"
    path.write_text('import logging\ndef handler(raw):\n    logging.info("pin=%d", raw)\n')
    findings = [
        Finding(
            rule_id=rule,
            message="log",
            severity=Severity.MEDIUM,
            category=Category.INJECTION,
            file_path=str(path),
            start_line=3,
        )
        for rule in ("TNT-LOG-001", "TNT-LOG-002")
    ]
    ctx = ScanContext(target_path=tmp_path, config=ScanConfig(target=tmp_path), result=ScanResult())
    kept = EnrichmentPass()._suppress_bounded_log_forging(findings, ctx)
    assert [f.rule_id for f in kept] == ["TNT-LOG-002"]


def test_budget_exhaustion_never_creates_a_clean_verdict():
    path = Path("sample.py")
    analysis = BoundedLogValues({path: ast.parse("def handler(raw):\n    logger.info(int(raw))")})
    analysis.budget = 0
    assert not analysis.safe_lines(path)


@pytest.mark.parametrize(
    "trailer",
    [
        "from custom import convert",
        "from custom import *",
        "def convert(value):\n    return value",
    ],
)
def test_rebound_helper_exports_are_not_trusted(tmp_path, trailer):
    helper, caller = tmp_path / "helper.py", tmp_path / "handler.py"
    trees = {
        helper: ast.parse("def convert(value):\n    return int(value)\n" + trailer),
        caller: ast.parse(
            "from helper import convert\ndef handler(raw):\n    logger.info(convert(raw))"
        ),
    }
    assert not BoundedLogValues(trees).safe_lines(caller)


def test_monkeypatched_builtin_is_not_trusted():
    path = Path("sample.py")
    source = "import builtins\nbuiltins.int = custom\ndef handler(raw):\n    logger.info(int(raw))"
    assert not BoundedLogValues({path: ast.parse(source)}).safe_lines(path)


@pytest.mark.parametrize(
    "setup,receiver,bounded",
    [
        ("import logging as output", "output", True),
        ("import logging\nlog = logging.getLogger(__name__)", "log", True),
        ("import logging\nlogging = custom", "logging", False),
        ("import custom as logging", "logging", False),
        ("import logging\nlogging.info = custom", "logging", False),
        ("import logging\nlog = logging.getLogger(__name__)\nlog = custom", "log", False),
        ("", "custom", False),
    ],
)
def test_unknown_argument_numeric_formats_require_standard_logging(setup, receiver, bounded):
    path = Path("sample.py")
    source = setup + "\ndef handler(raw):\n    " + receiver + '.info("value=%d", raw)\n'
    safe = BoundedLogValues({path: ast.parse(source)}).safe_lines(path)
    assert bool(safe) is bounded


def test_custom_registered_logger_does_not_inherit_numeric_format_proof():
    path = Path("sample.py")
    source = (
        "import logging\nlogging.setLoggerClass(CustomLogger)\n"
        'log = logging.getLogger(__name__)\ndef handler(raw):\n    log.info("%d", raw)'
    )
    assert not BoundedLogValues({path: ast.parse(source)}).safe_lines(path)
