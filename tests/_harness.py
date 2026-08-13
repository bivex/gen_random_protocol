"""Shared helpers for the C/SPIN integration tests.

These tests codify the manual verification done during review: they generate a
protocol, compile the emitted C, run a runtime harness, and (when SPIN is
installed) model-check the Promela output. They skip gracefully when the
required toolchain (gcc / spin) is absent, so the suite runs anywhere Python
runs.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def generate(proto_dir: Path, *, seed_hex: str, pattern: str = "auto",
             run_spin: bool = False):
    """Generate a protocol into proto_dir and return the Protocol entity.

    Thin wrapper around the application service so tests exercise the real
    CLI code path (generator + emitters + optional verifier).
    """
    from gen_protocol.application.compiler_service import ProtocolCompilerService
    proto = ProtocolCompilerService(out_dir=proto_dir).generate_random(
        seed_hex=seed_hex, pattern=pattern, run_spin=run_spin,
    )
    return proto


def compile_c(src: Path, out: Path, *extra) -> subprocess.CompletedProcess:
    """Compile a .c (or several) with gcc -std=c99 -Wall -Wextra."""
    return subprocess.run(
        ["gcc", "-std=c99", "-Wall", "-Wextra", *extra, str(src), "-o", str(out)],
        capture_output=True, text=True,
    )
