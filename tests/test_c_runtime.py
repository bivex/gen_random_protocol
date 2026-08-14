"""Integration test: the generated C runtime behaves correctly.

Compiles a small harness against a generated protocol and exercises, at runtime:
  - header CRC happy-path validation,
  - CRC mismatch detection on tamper,
  - the sliding-window anti-replay (forward / replay / out-of-order / NULL).

This is the test that catches real correctness bugs (CRC, endian swap, replay
logic) — not just "does it compile". Skips if gcc is not installed.
"""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests._harness import generate, have

# Harness source. {name} is the lower-cased protocol name; {op} is the first
# emitted opcode macro (so hdr_validate's opcode whitelist is satisfied).
# Literal C braces are doubled for str.format.
_HARNESS = """
#include "{name}.h"
#include <stdio.h>
#include <stdint.h>
#define TEST_OPCODE {op}

int main(void) {{
    int pass = 0, fail = 0;

    /* ---- header CRC round-trip ---- */
    {name}_hdr_t hdr;
    uint8_t payload[1024] = {{0}};
    uint16_t exp_len = {name}_expected_payload_len(TEST_OPCODE);
    {name}_hdr_init(&hdr, TEST_OPCODE, 0x1234u, 5u, exp_len);
    hdr.crc32 = {name}_frame_crc(&hdr, payload, exp_len);
    {name}_hdr_encode(&hdr);
    {name}_hdr_decode(&hdr);
    if ({name}_hdr_validate(&hdr, payload, exp_len) == 0) pass++; else fail++;   /* happy path */

    hdr.crc32 ^= 0xDEADBEEFu;                                                  /* tamper crc field */
    if ({name}_hdr_validate(&hdr, payload, exp_len) == -5) pass++; else fail++; /* CRC mismatch */

    /* ---- sliding-window anti-replay ---- */
    {name}_replay_state_t st = {{0}};
    if ({name}_replay_check(&st, 5)  == 1) pass++; else fail++;   /* first frame */
    if ({name}_replay_check(&st, 5)  == 0) pass++; else fail++;   /* exact replay */
    if ({name}_replay_check(&st, 10) == 1) pass++; else fail++;   /* forward */
    if ({name}_replay_check(&st, 7)  == 1) pass++; else fail++;   /* out-of-order, fresh */
    if ({name}_replay_check(&st, 7)  == 0) pass++; else fail++;   /* replay of seen */
    if ({name}_replay_check(&st, 11) == 1) pass++; else fail++;   /* forward */
    if ({name}_replay_check(&st, 10) == 0) pass++; else fail++;   /* 10 seen -> reject */
    if ({name}_replay_check(NULL, 5) == 0) pass++; else fail++;   /* NULL safety */

    printf("RESULT pass=%d fail=%d\\n", pass, fail);
    return fail ? 1 : 0;
}}
"""


class TestCRuntime(unittest.TestCase):
    def setUp(self):
        if not have("gcc"):
            self.skipTest("gcc not available")

    def test_header_crc_and_replay(self):
        tmp = Path(tempfile.mkdtemp())
        proto = generate(tmp, seed_hex="7" * 32, pattern="rpc")
        name = proto.name.lower()

        header_text = (tmp / f"{name}.h").read_text()
        m = re.search(r"#define\s+([A-Z0-9_]+_MSG_\w+)\s+0x[0-9A-Fa-f]+U", header_text)
        self.assertIsNotNone(m, "no opcode macro found in generated header")

        harness_src = _HARNESS.format(name=name, op=m.group(1))
        harness_c = tmp / "harness.c"
        harness_c.write_text(harness_src)
        exe = tmp / "harness"

        cc = subprocess.run(
            ["gcc", "-std=c99", "-Wall", "-Wextra", f"-I{tmp}",
             str(harness_c), str(tmp / f"{name}.c"), "-o", str(exe)],
            capture_output=True, text=True,
        )
        self.assertEqual(cc.returncode, 0, f"harness compile failed:\n{cc.stderr}")

        run = subprocess.run([str(exe)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0,
                         f"harness runtime failed:\n{run.stdout}\n{run.stderr}")
        self.assertIn("RESULT pass=10 fail=0", run.stdout,
                       f"unexpected harness result:\n{run.stdout}")


if __name__ == "__main__":
    unittest.main()
