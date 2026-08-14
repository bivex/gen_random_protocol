"""
Tests for multi-session anti-replay manager table (<proto>_replay_table_t) under high load (10k sessions).
"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from random import Random

from gen_protocol.domain.generator import ProtocolGenerator
from gen_protocol.adapters.emitters.c_header import CHeaderEmitter
from gen_protocol.adapters.emitters.c_source import CSourceEmitter


class TestReplayTable(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        gen = ProtocolGenerator(Random(5555), "55"*16)
        self.proto = gen.generate(pattern="reqrsp")

    def test_replay_table_10k_sessions(self):
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
#include <stdbool.h>

int main(void) {{
    {self.proto.name.lower()}_replay_table_t tbl;
    {self.proto.name.lower()}_replay_table_init(&tbl);

    /* 1. Basic Single Session Operations */
    assert({self.proto.name.lower()}_replay_table_check(&tbl, 100, 1) == true);  /* new session, seq 1 */
    assert({self.proto.name.lower()}_replay_table_check(&tbl, 100, 1) == false); /* replay seq 1 */
    assert({self.proto.name.lower()}_replay_table_check(&tbl, 100, 2) == true);  /* forward seq 2 */
    assert({self.proto.name.lower()}_replay_table_check(&tbl, 100, 5) == true);  /* forward seq 5 */
    assert({self.proto.name.lower()}_replay_table_check(&tbl, 100, 3) == true);  /* out-of-order fresh seq 3 */
    assert({self.proto.name.lower()}_replay_table_check(&tbl, 100, 3) == false); /* replay seq 3 */

    /* 2. Distinct Sessions Isolation */
    assert({self.proto.name.lower()}_replay_table_check(&tbl, 200, 1) == true);  /* session 200 seq 1 */
    assert({self.proto.name.lower()}_replay_table_check(&tbl, 100, 4) == true);  /* session 100 seq 4 */
    assert({self.proto.name.lower()}_replay_table_check(&tbl, 200, 1) == false); /* session 200 replay */

    /* 3. High Load Test: 10,000 unique sessions */
    for (uint32_t s = 1; s <= 10000; s++) {{
        /* Each new or active session receiving initial sequence */
        bool ok = {self.proto.name.lower()}_replay_table_check(&tbl, s, 10);
        assert(ok == true);

        /* Exact replay must be rejected */
        bool replay = {self.proto.name.lower()}_replay_table_check(&tbl, s, 10);
        assert(replay == false);

        /* Forward sequence must be accepted */
        bool fwd = {self.proto.name.lower()}_replay_table_check(&tbl, s, 11);
        assert(fwd == true);
    }}

    printf("REPLAY_TABLE_10K_OK\\n");
    return 0;
}}
"""
        runner_file = self.tmp_dir / "runner.c"
        runner_file.write_text(main_c)

        exe_file = self.tmp_dir / "test_replay_tbl_bin"
        compile_cmd = ["gcc", "-Wall", "-Wextra", "-Werror", "-O2", "-o", str(exe_file), str(c_file), str(runner_file)]
        cr = subprocess.run(compile_cmd, capture_output=True, text=True)
        self.assertEqual(cr.returncode, 0, f"Compilation failed:\n{cr.stderr}")

        rr = subprocess.run([str(exe_file)], capture_output=True, text=True)
        self.assertEqual(rr.returncode, 0, f"Execution failed:\n{rr.stderr}")
        self.assertIn("REPLAY_TABLE_10K_OK", rr.stdout)


if __name__ == "__main__":
    unittest.main()
