"""Shared classification constants for non-source scan artifacts."""

from __future__ import annotations

import re
from pathlib import Path

DEPENDENCY_MANIFEST_PATTERNS: tuple[str, ...] = (
    r"requirements.*\.txt$",
    r"pyproject\.toml$",
    r"Pipfile$",
    r"Pipfile\.lock$",
    r"poetry\.lock$",
    r"uv\.lock$",
    r"package\.json$",
    r"package-lock\.json$",
    r"npm-shrinkwrap\.json$",
    r"yarn\.lock$",
    r"pnpm-lock\.yaml$",
    r"pom\.xml$",
    r"packages\.config$",
    r"packages\.lock\.json$",
    r"[^/]+\.csproj$",
    r"build\.gradle$",
    r"build\.gradle\.kts$",
    r"libs\.versions\.toml$",
    r"go\.mod$",
    r"go\.work$",
    r"Cargo\.toml$",
    r"Cargo\.lock$",
    r"Gemfile$",
    r"Gemfile\.lock$",
    r"composer\.json$",
    r"composer\.lock$",
)

DEPENDENCY_SKIP_DIRS = frozenset({
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
})

_DEPENDENCY_MANIFEST_REGEXES = tuple(
    re.compile(pattern, re.I) for pattern in DEPENDENCY_MANIFEST_PATTERNS
)


# Every extension Hayward's own directory discovery reads, so a model file
# Hayward can analyse is never left out of Rowan's inventory.
# tests/test_artifact_inventory.py fails if the two sets drift apart.
#
# The compressed tar forms are listed in full. ``Path.suffix`` of
# ``weights.tar.gz`` is ``.gz``, and Hayward's ``discover_files`` globs
# ``*.tar.gz`` (then ``scan_file`` maps that name back to tar). Matching
# only the last suffix would drop those archives.
MODEL_ARTIFACT_EXTENSIONS: tuple[str, ...] = (
    ".pkl", ".pickle", ".pth", ".pt", ".ptl", ".ckpt", ".th", ".mar", ".nemo",
    ".safetensors", ".gguf", ".h5", ".hdf5", ".keras", ".onnx", ".pb",
    ".npy", ".npz", ".joblib", ".7z", ".tar",
    ".tgz", ".tbz2", ".txz", ".tar.gz", ".tar.bz2", ".tar.xz",
    ".tflite", ".skops", ".pmml",
    ".bin", ".zip", ".json",
    # transformers chat templates. Same discovery class as ``.json`` configs.
    ".jinja",
)

# Exact filenames Hayward globs in addition to extensions. ``.txt`` and
# ``.model`` are too common to discover by suffix; ``discover_files`` names
# these tokenizer files one by one.
MODEL_ARTIFACT_FILENAMES: tuple[str, ...] = (
    "merges.txt",
    "vocab.txt",
    "tokenizer.model",
    "spiece.model",
    "spm.model",
    "sentencepiece.bpe.model",
)

# Inventory order: extensions, then the exact filenames.
MODEL_ARTIFACT_DISCOVERY: tuple[str, ...] = (
    MODEL_ARTIFACT_EXTENSIONS + MODEL_ARTIFACT_FILENAMES
)

# Longer suffixes first so ``weights.tar.gz`` matches ``.tar.gz`` rather
# than a shorter suffix that is also a string ending of the name.
_MODEL_ARTIFACT_SUFFIXES_LONGEST_FIRST: tuple[str, ...] = tuple(
    sorted(MODEL_ARTIFACT_EXTENSIONS, key=len, reverse=True)
)
_MODEL_ARTIFACT_EXACT_NAMES = frozenset(MODEL_ARTIFACT_FILENAMES)


def is_dependency_manifest(path: Path) -> bool:
    """Return whether a path name is one of the supported SCA formats."""

    return any(regex.match(path.name) for regex in _DEPENDENCY_MANIFEST_REGEXES)


def model_artifact_key(path: Path) -> str | None:
    """Return the registry entry ``path`` matches, or None.

    Case-sensitive, matching Hayward's ``rglob``. Upper-case suffixes are
    left undiscovered, as they were when discovery used ``Path.suffix``.
    """

    name = path.name
    if name in _MODEL_ARTIFACT_EXACT_NAMES:
        return name
    for extension in _MODEL_ARTIFACT_SUFFIXES_LONGEST_FIRST:
        if name.endswith(extension):
            return extension
    return None


def is_model_artifact(path: Path) -> bool:
    """Return whether Hayward's directory walk would pick this path up."""

    return model_artifact_key(path) is not None
