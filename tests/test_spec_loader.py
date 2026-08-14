"""
Unit tests for YamlSpecLoader: determinism, seed reproducibility, custom magic, validations, and code-injection prevention.
"""

import tempfile
import unittest
from pathlib import Path

from gen_protocol.adapters.idl.yaml_loader import YamlSpecLoader


class TestSpecLoader(unittest.TestCase):
    def setUp(self):
        self.loader = YamlSpecLoader()
        self.tmp_dir = Path(tempfile.mkdtemp())

    def test_deterministic_default_seed_and_magic(self):
        yaml_content = """
protocol:
  name: DETERMINISTIC_PROTO
  version: 1.0.0
  endian: big
  pattern: rpc

messages:
  - name: REQ
    opcode: 0x0001
    direction: C->S
    fields:
      - { name: id, type: u32 }
"""
        f = self.tmp_dir / "spec1.yaml"
        f.write_text(yaml_content)

        p1 = self.loader.load(f)
        p2 = self.loader.load(f)

        # Exact same YAML without flags must produce the exact same seed & magic
        self.assertEqual(p1.seed, p2.seed)
        self.assertEqual(p1.magic, p2.magic)
        self.assertEqual(p1.name, "DETERMINISTIC_PROTO")

    def test_seed_override_reproducibility(self):
        yaml_content = """
protocol:
  name: SEED_PROTO
  version: 2.0.0
  endian: little
  pattern: reqrsp

messages:
  - name: PING
    opcode: 0x0010
    direction: C->S
    fields:
      - { name: seq, type: u32 }
"""
        f = self.tmp_dir / "spec2.yaml"
        f.write_text(yaml_content)

        fixed_seed = "1234567890abcdef1234567890abcdef"
        p = self.loader.load(f, seed=fixed_seed)
        self.assertEqual(p.seed, fixed_seed)

    def test_explicit_magic_in_yaml(self):
        yaml_content = """
protocol:
  name: MAGIC_PROTO
  version: 1.0.0
  magic: 0xCAFEBABE
  endian: big
  pattern: pubsub

messages:
  - name: EVENT
    opcode: 0x0020
    direction: S->C
    fields:
      - { name: payload, type: u8, array_size: 16 }
"""
        f = self.tmp_dir / "spec3.yaml"
        f.write_text(yaml_content)

        p = self.loader.load(f)
        self.assertEqual(p.magic, 0xCAFEBABE)

    def test_opcode_validation_errors(self):
        # Duplicate opcode
        yaml_dup = """
protocol:
  name: DUP_PROTO
messages:
  - { name: MSG1, opcode: 0x0005 }
  - { name: MSG2, opcode: 0x0005 }
"""
        f_dup = self.tmp_dir / "dup.yaml"
        f_dup.write_text(yaml_dup)
        with self.assertRaises(ValueError) as ctx:
            self.loader.load(f_dup)
        self.assertIn("duplicate opcode", str(ctx.exception))

        # Out of range opcode (0x0000 or > 0xFFFE)
        yaml_zero = """
protocol:
  name: ZERO_PROTO
messages:
  - { name: MSG0, opcode: 0x0000 }
"""
        f_zero = self.tmp_dir / "zero.yaml"
        f_zero.write_text(yaml_zero)
        with self.assertRaises(ValueError) as ctx:
            self.loader.load(f_zero)
        self.assertIn("out of range", str(ctx.exception))

    def test_field_validation_errors(self):
        # Missing field name
        yaml_missing_name = """
protocol:
  name: BAD_FIELD_PROTO
messages:
  - name: MSG
    opcode: 0x0001
    fields:
      - { type: u32 }
"""
        f = self.tmp_dir / "bad_field.yaml"
        f.write_text(yaml_missing_name)
        with self.assertRaises(ValueError) as ctx:
            self.loader.load(f)
        self.assertIn("must match regex", str(ctx.exception))

    def test_code_injection_prevention(self):
        # 1. Malicious field name with C statement injection
        yaml_inj_field = """
protocol:
  name: INJ_PROTO
messages:
  - name: MSG
    opcode: 0x0001
    fields:
      - { name: "x; system(\\"rm -rf /\\")", type: u32 }
"""
        f1 = self.tmp_dir / "inj_field.yaml"
        f1.write_text(yaml_inj_field)
        with self.assertRaises(ValueError) as ctx:
            self.loader.load(f1)
        self.assertIn("Invalid C field name", str(ctx.exception))

        # 2. Malicious message name with newline and preprocessor injection
        yaml_inj_msg = """
protocol:
  name: INJ_PROTO
messages:
  - name: "MSG\\n#include <evil.h>"
    opcode: 0x0001
"""
        f2 = self.tmp_dir / "inj_msg.yaml"
        f2.write_text(yaml_inj_msg)
        with self.assertRaises(ValueError) as ctx:
            self.loader.load(f2)
        self.assertIn("Invalid C message name", str(ctx.exception))

        # 3. Reserved keyword as field name
        yaml_res_field = """
protocol:
  name: INJ_PROTO
messages:
  - name: MSG
    opcode: 0x0001
    fields:
      - { name: "struct", type: u32 }
"""
        f3 = self.tmp_dir / "res_field.yaml"
        f3.write_text(yaml_res_field)
        with self.assertRaises(ValueError) as ctx:
            self.loader.load(f3)
        self.assertIn("cannot be a C reserved keyword", str(ctx.exception))

        # 4. Malicious enum name / member injection
        yaml_inj_enum = """
protocol:
  name: INJ_PROTO
enums:
  - name: "EVIL_ENUM; int backdoor()"
    members:
      - { name: "OK", value: 0 }
messages:
  - name: MSG
    opcode: 0x0001
"""
        f4 = self.tmp_dir / "inj_enum.yaml"
        f4.write_text(yaml_inj_enum)
        with self.assertRaises(ValueError) as ctx:
            self.loader.load(f4)
        self.assertIn("Invalid C enum name", str(ctx.exception))

        # 5. Comment sanitization check (strips C comment breakouts)
        yaml_comment = """
protocol:
  name: COMMENT_PROTO
messages:
  - name: MSG
    opcode: 0x0001
    description: "Legal description /* break-out */ int backdoor;"
    fields:
      - { name: valid_field, type: u32, comment: "Field comment */ inject;" }
"""
        f5 = self.tmp_dir / "comment.yaml"
        f5.write_text(yaml_comment)
        proto = self.loader.load(f5)
        self.assertNotIn("/*", proto.messages[0].description)
        self.assertNotIn("*/", proto.messages[0].description)
        self.assertNotIn("*/", proto.messages[0].fields[0].comment)


if __name__ == "__main__":
    unittest.main()
