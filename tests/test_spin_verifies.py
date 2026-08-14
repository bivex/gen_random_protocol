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

    def test_high_opcodes_pass_spin(self):
        """Regression: IDL opcodes above 0x00FE (16-bit wire values) must
        model-check cleanly. The model previously stored the opcode in a
        Promela `byte` with a hard-coded OPCODE_MAX=254, so any legal
        0x0100..0xFFFE opcode truncated to 0 and failed every assertion."""
        from gen_protocol.adapters.emitters.promela import PromelaEmitter
        from gen_protocol.adapters.idl.yaml_loader import YamlSpecLoader
        from gen_protocol.adapters.verifiers.spin_verifier import SpinVerifier

        tmp = Path(tempfile.mkdtemp())
        spec = tmp / "spec.yaml"
        spec.write_text(
            "protocol:\n"
            "  name: HIOP\n"
            "  version: 1.0.0\n"
            "  pattern: rpc\n"
            "messages:\n"
            "  - name: CALL\n"
            "    opcode: 0x0100\n"
            "    direction: C->S\n"
            "    fields: [{name: method_id, type: u16}]\n"
            "  - name: RESULT\n"
            "    opcode: 0x0101\n"
            "    direction: S->C\n"
            "    fields: [{name: status, type: u8}]\n"
        )
        proto = YamlSpecLoader().load(spec)

        pml_text = PromelaEmitter(proto).emit()
        self.assertIn("#define OPCODE_MAX 257", pml_text)  # derived, not hard-coded 254

        pml = tmp / "model.pml"
        pml.write_text(pml_text)
        result = SpinVerifier().verify(pml)
        self.assertTrue(
            result.get("passed") is True,
            f"SPIN verification did not pass for 16-bit opcodes: {result}",
        )


if __name__ == "__main__":
    unittest.main()
