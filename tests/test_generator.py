"""
Unit tests for gen_protocol domain generator and semantic rules.
"""

import unittest
from random import Random

from gen_protocol.adapters.emitters.c_source import CSourceEmitter
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


    def test_seq_validate_is_wraparound_safe(self):
        """Anti-replay must use a wraparound-safe signed delta and a UINT32_MAX
        init sentinel — not the naive `> last || last == 0` form (which accepted
        an exact replay of sequence 0 and bricked the session on rollover)."""
        proto = self.generator.generate()
        src = CSourceEmitter(proto).emit()

        start = src.index("_seq_validate(")
        body = src[start:src.index("}", start) + 1]

        self.assertIn("int32_t", body)                 # signed-delta comparison
        self.assertIn("0xFFFFFFFF", src)               # documented init sentinel
        self.assertNotIn("*last_seq == 0U", body)      # buggy init special-case gone
        self.assertNotIn("incoming_seq > *last_seq", body)  # naive non-wrap check gone


if __name__ == "__main__":
    unittest.main()
