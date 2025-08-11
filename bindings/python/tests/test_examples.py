#!/usr/bin/env python3

import subprocess
import os
from pathlib import Path
from typing import Any

EXAMPLES_DIR: str = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "examples")
)


def test_write_and_read_example(tmp_path: Path) -> None:
    archive_path: Path = tmp_path / "example.mla"
    # Run write.py in temp dir
    script: str = os.path.join(EXAMPLES_DIR, "write.py")
    subprocess.check_call(["python3", script], cwd=str(tmp_path))
    assert archive_path.exists()
    # Now run read.py and capture output
    script = os.path.join(EXAMPLES_DIR, "read.py")
    output: str = subprocess.check_output(
        ["python3", script], cwd=str(tmp_path), text=True
    )
    # Check for expected output from read.py
    assert "hello.txt" in output
    assert "data.bin" in output
