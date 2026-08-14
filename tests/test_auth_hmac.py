"""
Tests for embedded HMAC-SHA256 authentication, constant-time verification, and anti-tampering.
"""

import hmac
import hashlib
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from random import Random

from gen_protocol.domain.generator import ProtocolGenerator
from gen_protocol.adapters.emitters.c_header import CHeaderEmitter
from gen_protocol.adapters.emitters.c_source import CSourceEmitter


class TestAuthHMAC(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        gen = ProtocolGenerator(Random(12345), "1234567890abcdef1234567890abcdef")
        self.proto = gen.generate(pattern="reqrsp", auth="hmac-sha256")

    def test_c_emission_and_compilation(self):
        h_code = CHeaderEmitter(self.proto).emit()
        c_code = CSourceEmitter(self.proto).emit()

        h_file = self.tmp_dir / f"{self.proto.name.lower()}.h"
        c_file = self.tmp_dir / f"{self.proto.name.lower()}.c"

        h_file.write_text(h_code)
        c_file.write_text(c_code)

        # Write test main runner in C
        main_c = f"""
#include "{self.proto.name.lower()}.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {{
    {self.proto.header_struct_name} hdr;
    uint8_t payload[64];
    memset(payload, 0xAB, sizeof(payload));

    uint16_t op = {self.proto.messages[0].name};
    uint16_t exp_len = {self.proto.name.lower()}_expected_payload_len(op);
    assert(exp_len <= sizeof(payload));

    {self.proto.name.lower()}_hdr_init(&hdr, op, 0x11223344, 1, exp_len);
    hdr.crc32 = {self.proto.name.lower()}_frame_crc(&hdr, payload, exp_len);

    /* 1. Header validation must succeed */
    int res = {self.proto.name.lower()}_hdr_validate(&hdr, payload, exp_len);
    assert(res == {self.proto.name}_HDR_OK);

    /* 2. Calculate frame HMAC */
    const uint8_t key[32] = "super_secret_shared_hmac_key_32";
    uint8_t mac[32];
    {self.proto.name.lower()}_frame_mac(&hdr, payload, exp_len, key, sizeof(key), mac);

    /* 3. Verify valid MAC -> OK */
    int v_res = {self.proto.name.lower()}_mac_verify(&hdr, payload, exp_len, mac, key, sizeof(key));
    assert(v_res == {self.proto.name}_HDR_OK);

    /* 4. Verify tampered payload -> HDR_ERR_AUTH_FAIL */
    payload[0] ^= 0x01;
    int v_tamper = {self.proto.name.lower()}_mac_verify(&hdr, payload, exp_len, mac, key, sizeof(key));
    assert(v_tamper == {self.proto.name}_HDR_ERR_AUTH_FAIL);
    payload[0] ^= 0x01; /* restore */

    /* 5. Verify wrong key -> HDR_ERR_AUTH_FAIL */
    const uint8_t wrong_key[32] = "wrong_secret_shared_hmac_key_32";
    int v_wrong_key = {self.proto.name.lower()}_mac_verify(&hdr, payload, exp_len, mac, wrong_key, sizeof(wrong_key));
    assert(v_wrong_key == {self.proto.name}_HDR_ERR_AUTH_FAIL);

    /* 6. Verify tampered header sequence -> HDR_ERR_AUTH_FAIL */
    hdr.sequence = 999;
    int v_hdr_tamper = {self.proto.name.lower()}_mac_verify(&hdr, payload, exp_len, mac, key, sizeof(key));
    assert(v_hdr_tamper == {self.proto.name}_HDR_ERR_AUTH_FAIL);

    printf("HMAC_AUTH_OK\\n");
    return 0;
}}
"""
        runner_file = self.tmp_dir / "runner.c"
        runner_file.write_text(main_c)

        # Compile and execute
        exe_file = self.tmp_dir / "test_auth_bin"
        compile_cmd = ["gcc", "-Wall", "-Wextra", "-Werror", "-O2", "-o", str(exe_file), str(c_file), str(runner_file)]
        cr = subprocess.run(compile_cmd, capture_output=True, text=True)
        self.assertEqual(cr.returncode, 0, f"Compilation failed:\n{cr.stderr}")

        rr = subprocess.run([str(exe_file)], capture_output=True, text=True)
        self.assertEqual(rr.returncode, 0, f"Execution failed:\n{rr.stderr}")
        self.assertIn("HMAC_AUTH_OK", rr.stdout)


if __name__ == "__main__":
    unittest.main()
