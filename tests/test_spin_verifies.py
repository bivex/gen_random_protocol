"""Integration test: the generated Promela model passes SPIN verification.

Exercises the real Promela emitter + SpinVerifier (safety + liveness) on a
generated protocol. Skips if spin or gcc is not installed (e.g. default CI).
Run locally with: `python -m pytest tests/test_spin_verifies.py`
"""

import unittest
from pathlib import Path
from random import Random
import tempfile

from tests._harness import have


class TestSpinVerifies(unittest.TestCase):
    def setUp(self):
        if not (have("spin") and have("gcc")):
            self.skipTest("spin and/or gcc not available")

    def test_model_passes_spin(self):
        from gen_protocol.domain.generator import ProtocolGenerator
        from gen_protocol.adapters.emitters.promela import PromelaEmitter
        from gen_protocol.adapters.verifiers.spin_verifier import SpinVerifier

        tmp = Path(tempfile.mkdtemp())
        seed = "0123456789abcdef0123456789abcdef"
        seed_int = int.from_bytes(bytes.fromhex(seed), "big")
        proto = ProtocolGenerator(Random(seed_int), seed).generate(pattern="rpc")

        pml = tmp / "model.pml"
        pml.write_text(PromelaEmitter(proto).emit())

        result = SpinVerifier().verify(pml)
        self.assertTrue(
            result.get("passed") is True,
            f"SPIN verification did not pass: {result}",
        )


if __name__ == "__main__":
    unittest.main()
