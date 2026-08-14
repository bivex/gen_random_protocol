"""
Tests for schema payload length validation (ERR_LEN_SCHEMA).
"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from random import Random

from gen_protocol.domain.generator import ProtocolGenerator
from gen_protocol.adapters.emitters.c_header import CHeaderEmitter
from gen_protocol.adapters.emitters.c_source import CSourceEmitter


class TestSchemaLengthValidation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        gen = ProtocolGenerator(Random(999), "99"*16)
        self.proto = gen.generate(pattern="rpc")

    def test_schema_length_mismatch_rejection(self):
        h_code = CHeaderEmitter(self.proto).emit()
        c_code = CSourceEmitter(self.proto).emit()

        h_file = self.tmp_dir / f"{self.proto.name.lower()}.h"
        c_file = self.tmp_dir / f"{self.proto.name.lower()}.c"

        h_file.write_text(h_code)
        c_file.write_text(c_code)

        main_c = f"""
#include "{self.proto.name.lower()}.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {{
    {self.proto.header_struct_name} hdr;
    uint16_t op = {self.proto.messages[0].name};
    uint16_t exp_len = {self.proto.name.lower()}_expected_payload_len(op);

    uint8_t payload[1024];
    memset(payload, 0, sizeof(payload));

    /* 1. Valid payload matching schema length -> HDR_OK */
    {self.proto.name.lower()}_hdr_init(&hdr, op, 123, 1, exp_len);
    hdr.crc32 = {self.proto.name.lower()}_frame_crc(&hdr, payload, exp_len);
    int res = {self.proto.name.lower()}_hdr_validate(&hdr, payload, exp_len);
    assert(res == {self.proto.name}_HDR_OK);

    /* 2. Truncated payload claiming wrong schema length -> HDR_ERR_LEN_SCHEMA */
    uint16_t truncated_len = (exp_len > 1) ? (exp_len - 1) : (exp_len + 1);
    {self.proto.name.lower()}_hdr_init(&hdr, op, 123, 1, truncated_len);
    hdr.crc32 = {self.proto.name.lower()}_frame_crc(&hdr, payload, truncated_len);
    int res_schema = {self.proto.name.lower()}_hdr_validate(&hdr, payload, truncated_len);
    assert(res_schema == {self.proto.name}_HDR_ERR_LEN_SCHEMA);

    printf("SCHEMA_LEN_OK\\n");
    return 0;
}}
"""
        runner_file = self.tmp_dir / "runner.c"
        runner_file.write_text(main_c)

        exe_file = self.tmp_dir / "test_schema_bin"
        compile_cmd = ["gcc", "-Wall", "-Wextra", "-Werror", "-O2", "-o", str(exe_file), str(c_file), str(runner_file)]
        cr = subprocess.run(compile_cmd, capture_output=True, text=True)
        self.assertEqual(cr.returncode, 0, f"Compilation failed:\n{cr.stderr}")

        rr = subprocess.run([str(exe_file)], capture_output=True, text=True)
        self.assertEqual(rr.returncode, 0, f"Execution failed:\n{rr.stderr}")
        self.assertIn("SCHEMA_LEN_OK", rr.stdout)


if __name__ == "__main__":
    unittest.main()
