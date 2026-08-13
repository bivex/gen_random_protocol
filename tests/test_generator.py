"""
Unit tests for gen_protocol domain generator and semantic rules.
"""

import unittest
from random import Random

from gen_protocol.domain.generator import ProtocolGenerator
from gen_protocol.domain.types import C_TYPES, FIELD_SEMANTIC_RULES


class TestProtocolGeneratorSemantics(unittest.TestCase):
    def setUp(self):
        self.rng = Random(42)
        self.generator = ProtocolGenerator(self.rng, seed="42"*16)

    def test_semantic_field_rules(self):
        proto = self.generator.generate(n_messages=10, max_fields=10)

        for msg in proto.messages:
            for field in msg.fields:
                name = field.name.lower()
                # Check length semantics
                if any(k in name for k in ("len", "length", "size", "offset")):
                    self.assertIn(field.ctype, ("uint16_t", "uint32_t", "uint64_t"))
                    self.assertIsNone(field.bits, f"Field {field.name} must not be a bitfield")

                # Check reserved / padding semantics
                if any(k in name for k in ("reserved", "padding", "pad")):
                    self.assertIn(field.ctype, ("uint8_t", "uint16_t", "uint32_t"))
                    self.assertIsNone(field.bits, f"Field {field.name} must not be a bitfield")

                # Check signature / hash / key / mac semantics
                if any(k in name for k in ("signature", "sig", "mac", "hash", "key", "token")):
                    self.assertEqual(field.ctype, "uint8_t")
                    self.assertIsNotNone(field.array_size, f"Field {field.name} should be a byte array")

                # Check code / error semantics
                if any(k in name for k in ("code", "reason", "opcode", "ttl")):
                    self.assertNotIn(field.ctype, ("float", "double"))

    def test_message_verb_uniqueness(self):
        proto = self.generator.generate(n_messages=20, max_fields=5)
        names = [m.name for m in proto.messages]
        # Ensure no _1 suffixes caused by duplicate verbs
        for name in names:
            self.assertFalse(name.endswith("_1"), f"Message name {name} has ugly suffix")

    def test_reproducibility(self):
        rng1 = Random(12345)
        g1 = ProtocolGenerator(rng1, seed="12345678901234567890123456789012")
        p1 = g1.generate()

        rng2 = Random(12345)
        g2 = ProtocolGenerator(rng2, seed="12345678901234567890123456789012")
        p2 = g2.generate()

        self.assertEqual(p1.name, p2.name)
        self.assertEqual(len(p1.messages), len(p2.messages))
        for m1, m2 in zip(p1.messages, p2.messages):
            self.assertEqual(m1.name, m2.name)
            self.assertEqual(m1.opcode, m2.opcode)


if __name__ == "__main__":
    unittest.main()
