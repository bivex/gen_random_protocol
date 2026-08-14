"""
Tests for libFuzzer harness emission and seed corpus generation.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from random import Random

from gen_protocol.domain.generator import ProtocolGenerator
from gen_protocol.adapters.emitters.c_header import CHeaderEmitter
from gen_protocol.adapters.emitters.c_source import CSourceEmitter
from gen_protocol.adapters.emitters.fuzz_harness import FuzzHarnessEmitter, generate_seed_corpus


class TestFuzzHarness(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        gen = ProtocolGenerator(Random(777), "77"*16)
        self.proto = gen.generate(pattern="fsm", auth="hmac-sha256")

    def test_fuzz_harness_and_seed_corpus(self):
        h_code = CHeaderEmitter(self.proto).emit()
        c_code = CSourceEmitter(self.proto).emit()
        fuzz_code = FuzzHarnessEmitter(self.proto).emit()

        h_file = self.tmp_dir / f"{self.proto.name.lower()}.h"
        c_file = self.tmp_dir / f"{self.proto.name.lower()}.c"
        fuzz_file = self.tmp_dir / f"{self.proto.name.lower()}_fuzz.c"

        h_file.write_text(h_code)
        c_file.write_text(c_code)
        fuzz_file.write_text(fuzz_code)

        # 1. Check generated fuzz harness contains LLVMFuzzerTestOneInput
        self.assertIn("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)", fuzz_code)
        self.assertIn(f"{self.proto.name.lower()}_hdr_validate", fuzz_code)

        # 2. Generate seed corpus
        corpus_dir = self.tmp_dir / "corpus"
        seeds = generate_seed_corpus(self.proto, corpus_dir)
        self.assertEqual(len(seeds), len(self.proto.messages))
        for s in seeds:
            self.assertTrue(s.exists())
            self.assertGreater(s.stat().st_size, 22)

        # 3. Write a standalone test runner that feeds all corpus seeds to LLVMFuzzerTestOneInput
        main_c = f"""
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(void) {{
    const char *seeds[] = {{
""" + ",\n".join(f'        "{s.resolve()}"' for s in seeds) + f"""
    }};
    size_t num_seeds = sizeof(seeds) / sizeof(seeds[0]);

    for (size_t i = 0; i < num_seeds; i++) {{
        FILE *f = fopen(seeds[i], "rb");
        assert(f != NULL);
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);

        uint8_t *buf = (uint8_t *)malloc((size_t)sz);
        assert(buf != NULL);
        size_t nread = fread(buf, 1, (size_t)sz, f);
        assert(nread == (size_t)sz);
        fclose(f);

        int r = LLVMFuzzerTestOneInput(buf, (size_t)sz);
        assert(r == 0);
        free(buf);
    }}

    printf("FUZZ_HARNESS_OK\\n");
    return 0;
}}
"""
        runner_file = self.tmp_dir / "fuzz_runner.c"
        runner_file.write_text(main_c)

        exe_file = self.tmp_dir / "fuzz_test_bin"
        compile_cmd = ["gcc", "-Wall", "-Wextra", "-Werror", "-O2", "-o", str(exe_file), str(c_file), str(fuzz_file), str(runner_file)]
        cr = subprocess.run(compile_cmd, capture_output=True, text=True)
        self.assertEqual(cr.returncode, 0, f"Fuzz runner compilation failed:\n{cr.stderr}")

        rr = subprocess.run([str(exe_file)], capture_output=True, text=True)
        self.assertEqual(rr.returncode, 0, f"Fuzz runner execution failed:\n{rr.stderr}")
        self.assertIn("FUZZ_HARNESS_OK", rr.stdout)


if __name__ == "__main__":
    unittest.main()
