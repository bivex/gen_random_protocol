"""Integration test: every protocol pattern must emit C that compiles clean.

Regression guard for the emitter layer (header/source/promela) across all five
protocol patterns. Skips if gcc is not installed.
"""

import tempfile
import unittest
from pathlib import Path

from tests._harness import compile_c, generate, have

PATTERNS = ["reqrsp", "stream", "pubsub", "rpc", "fsm"]
# deterministic hex seeds per pattern (must be 32 hex chars)
SEEDS = {"reqrsp": "1" * 32, "stream": "2" * 32, "pubsub": "3" * 32,
         "rpc": "4" * 32, "fsm": "5" * 32}


class TestCCompiles(unittest.TestCase):
    def setUp(self):
        if not have("gcc"):
            self.skipTest("gcc not available")

    def test_each_pattern_compiles(self):
        for pattern in PATTERNS:
            with self.subTest(pattern=pattern):
                tmp = Path(tempfile.mkdtemp())
                proto = generate(tmp, seed_hex=SEEDS[pattern], pattern=pattern)
                c_file = tmp / f"{proto.name.lower()}.c"
                r = compile_c(c_file, tmp / "out.o", "-c")
                self.assertEqual(
                    r.returncode, 0,
                    f"{pattern}: generated C failed to compile:\n{r.stderr}",
                )


if __name__ == "__main__":
    unittest.main()
