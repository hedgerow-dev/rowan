"""Shared dependency/model artifact inventory boundaries and reuse."""

from __future__ import annotations

from pathlib import Path

from hayward import ModelFileScanner

from rowan.artifacts import MODEL_ARTIFACT_DISCOVERY, model_artifact_key
from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext, SourceInventory
from rowan.passes.file_scan import FileScanPass
from rowan.passes.mcp_config import MCPConfigScanPass
from rowan.passes.mfv import ModelFileScanPass
from rowan.passes.sca import SCAPass


def _context(root: Path, **config_options) -> ScanContext:
    return ScanContext(
        target_path=root,
        config=ScanConfig(target=root, **config_options),
        result=ScanResult(),
    )


def _publish(root: Path, **config_options) -> ScanContext:
    context = _context(root, **config_options)
    FileScanPass(rules=[]).run(context)
    assert context.source_inventory is not None
    return context


def _signatures(result: ScanResult) -> list[tuple[str, str, int]]:
    return sorted(
        (finding.rule_id, finding.file_path, finding.start_line)
        for finding in result.findings
    )


def test_single_traversal_classifies_artifacts_without_changing_source_count(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "weights.pkl").write_bytes(b"not a pickle")
    (tmp_path / "mcp.json").write_text('{"mcpServers": {}}\n', encoding="utf-8")

    real_rglob = Path.rglob
    walks = 0

    def counted_rglob(self: Path, pattern: str):
        nonlocal walks
        walks += 1
        return real_rglob(self, pattern)

    monkeypatch.setattr(Path, "rglob", counted_rglob)
    context = _publish(tmp_path, languages=["python"])

    assert walks == 1
    assert context.source_inventory is not None
    assert [source.path.name for source in context.source_inventory.files] == ["app.py"]
    assert [path.name for path in context.source_inventory.dependency_manifests] == [
        "package.json"
    ]
    # .json is a model artifact too: Hayward checks HF config files for
    # auto_map / trust_remote_code / chat_template.
    assert sorted(path.name for path in context.source_inventory.model_artifacts) == [
        "mcp.json", "package.json", "weights.pkl"
    ]
    assert [path.name for path in context.source_inventory.mcp_config_files] == [
        "mcp.json"
    ]


def test_artifact_inventory_preserves_pass_specific_boundaries(tmp_path: Path) -> None:
    (tmp_path / ".rowanignore").write_text(
        "hidden/requirements.txt\nhidden/model.pkl\n", encoding="utf-8"
    )
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    manifest = hidden / "requirements.txt"
    manifest.write_text("requests==2.31.0\n", encoding="utf-8")
    model = hidden / "model.pkl"
    model.write_bytes(b"not a pickle")

    vendor = tmp_path / "vendor"
    vendor.mkdir()
    vendored_manifest = vendor / "package.json"
    vendored_manifest.write_text("{}\n", encoding="utf-8")
    (vendor / "vendored.pkl").write_bytes(b"not a pickle")

    node_modules = tmp_path / "node_modules" / "dep"
    node_modules.mkdir(parents=True)
    (node_modules / "package.json").write_text("{}\n", encoding="utf-8")
    (node_modules / "dep.pkl").write_bytes(b"not a pickle")

    context = _publish(tmp_path, languages=["python"], max_file_bytes=1)
    inventory = context.source_inventory
    assert inventory is not None
    # rglob order is filesystem-specific (ext4 differs from APFS).
    assert sorted(inventory.dependency_manifests) == [manifest, vendored_manifest]
    # Model files follow .rowanignore like source files; manifests still don't.
    assert inventory.model_artifacts == ()
    assert inventory.files == ()


def test_artifact_inventory_ignores_directories_named_like_manifests(
    tmp_path: Path,
) -> None:
    (tmp_path / "package.json").mkdir()
    (tmp_path / "requirements.txt").mkdir()

    inventory = _publish(tmp_path).source_inventory

    assert inventory is not None
    assert inventory.dependency_manifests == ()
    assert SCAPass()._find_dep_files(tmp_path) == []


def test_artifact_inventory_rejects_external_symlinks(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    try:
        manifest = outside / "requirements.txt"
        manifest.write_text("requests==2.31.0\n", encoding="utf-8")
        model = outside / "model.pkl"
        model.write_bytes(b"not a pickle")
        (tmp_path / "requirements.txt").symlink_to(manifest)
        (tmp_path / "model.pkl").symlink_to(model)

        inventory = _publish(tmp_path).source_inventory
        assert inventory is not None
        assert inventory.dependency_manifests == ()
        assert inventory.model_artifacts == ()
    finally:
        manifest.unlink(missing_ok=True)
        model.unlink(missing_ok=True)
        outside.rmdir()


def test_sca_inventory_matches_standalone_discovery_without_second_walk(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}\n", encoding="utf-8")
    sca = SCAPass()
    standalone = sca._find_dep_files(tmp_path)
    context = _publish(tmp_path)

    def unexpected_walk(self: Path, pattern: str):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    assert sca._find_dep_files(
        tmp_path, context.source_inventory.dependency_manifests
    ) == standalone


def test_mfv_inventory_matches_standalone_findings_without_second_walk(
    tmp_path: Path, monkeypatch
) -> None:
    # A protocol-0 pickle that references the denied os.system global.
    (tmp_path / "payload.pkl").write_bytes(b"cos\nsystem\n(S'id'\ntR.")
    standalone = ModelFileScanner().scan_directory(tmp_path)
    context = _publish(tmp_path)

    def unexpected_walk(self: Path, pattern: str):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    reused = ModelFileScanPass().run(context)
    assert sorted((f.rule_id, f.file_path) for f in reused.findings) == sorted(
        (f.rule_id, f.file_path) for f in standalone
    )


def test_mcp_config_inventory_matches_standalone_without_second_walk(
    tmp_path: Path, monkeypatch
) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        '{"mcpServers":{"fs":{"command":"server-filesystem","args":["/"]}}}',
        encoding="utf-8",
    )
    context = _publish(tmp_path, languages=["python"])

    def unexpected_walk(self: Path, pattern: str):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    result = MCPConfigScanPass().run(context)

    assert [finding.rule_id for finding in result.findings] == ["MCP-CONFIG-002"]


def test_empty_artifact_inventory_never_widens_scope(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "payload.pkl").write_bytes(b"cos\nsystem\n(S'id'\ntR.")
    context = _context(tmp_path)
    context.source_inventory = SourceInventory()

    def unexpected_walk(self: Path, pattern: str):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    assert SCAPass().run(context).findings == []
    assert ModelFileScanPass().run(context).findings == []
    assert MCPConfigScanPass().run(context).findings == []


def test_model_discovery_extension_registry_matches_scanner() -> None:
    """Rowan's registry is exactly what Hayward's directory walk globs.

    ``discover_files`` unions the format map with the ambiguous, config,
    and template extensions, then adds the exact tokenizer filenames.
    """

    scanner = ModelFileScanner()
    discovered = (
        set(scanner._format_map)
        | set(scanner._AMBIGUOUS_EXTENSIONS)
        | set(scanner._CONFIG_EXTENSIONS)
        | set(scanner._TEMPLATE_EXTENSIONS)
        | set(scanner._TOKENIZER_DATA_NAMES)
    )
    assert discovered == set(MODEL_ARTIFACT_DISCOVERY)


def test_multipart_tar_and_tokenizer_names_are_inventoried(tmp_path: Path) -> None:
    # Path.suffix of these is .gz/.bz2/.xz/.txt, which is not the registry key.
    (tmp_path / "weights.tar.gz").write_bytes(b"not a tar")
    (tmp_path / "weights.tar.bz2").write_bytes(b"not a tar")
    (tmp_path / "weights.tar.xz").write_bytes(b"not a tar")
    (tmp_path / "weights.tgz").write_bytes(b"not a tar")
    (tmp_path / "weights.tbz2").write_bytes(b"not a tar")
    (tmp_path / "weights.txz").write_bytes(b"not a tar")
    (tmp_path / "chat_template.jinja").write_text("{{ bos }}", encoding="utf-8")
    (tmp_path / "merges.txt").write_text("a b\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not a tokenizer\n", encoding="utf-8")
    (tmp_path / "data.gz").write_bytes(b"not a tar")
    (tmp_path / "model.hdf5").write_bytes(b"not hdf5")

    inventory = _publish(tmp_path).source_inventory
    assert inventory is not None
    assert sorted(path.name for path in inventory.model_artifacts) == [
        "chat_template.jinja",
        "merges.txt",
        "model.hdf5",
        "weights.tar.bz2",
        "weights.tar.gz",
        "weights.tar.xz",
        "weights.tbz2",
        "weights.tgz",
        "weights.txz",
    ]
    assert model_artifact_key(tmp_path / "weights.tar.gz") == ".tar.gz"
    assert model_artifact_key(tmp_path / "model.hdf5") == ".hdf5"
    assert model_artifact_key(tmp_path / "notes.txt") is None
    assert model_artifact_key(tmp_path / "data.gz") is None
