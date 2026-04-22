"""Smoke tests for the Dagger pipeline module.

These tests verify the module's structure without launching a real
Dagger engine (which would duplicate CI coverage).
"""

import importlib.util
from pathlib import Path


def test_module_imports():
    """The pipeline module can be imported without side effects."""
    module_path = Path(__file__).parent.parent / "src" / "mla" / "main.py"
    spec = importlib.util.spec_from_file_location("mla_pipeline", module_path)
    assert spec is not None
    assert spec.loader is not None


def test_expected_steps_exposed():
    """All expected pipeline steps are defined in the module source."""
    module_path = Path(__file__).parent.parent / "src" / "mla" / "main.py"
    source = module_path.read_text()
    expected = [
        "rust_fmt",
        "rust_clippy",
        "rust_test",
        "rust_audit",
        "cargo_deny",
        "sbom",
        "grype_scan",
    ]
    for step in expected:
        assert f"def {step}" in source, f"missing step: {step}"
