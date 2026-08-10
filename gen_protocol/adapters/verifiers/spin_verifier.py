"""
Adapter invoking SPIN formal verifier CLI tool on Promela models.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict
from gen_protocol.ports.verifier import ModelVerifier


class SpinVerifier(ModelVerifier):
    def verify(self, pml_file: Path) -> Dict[str, Any]:
        """Runs SPIN safety (DSAFETY) and liveness (-a) model checking."""
        if not shutil.which("spin"):
            print("[spin]  warning: 'spin' executable not found in PATH; skipping model checking.")
            return {"error": "spin_not_found"}

        if not shutil.which("gcc"):
            print("[spin]  warning: 'gcc' executable not found in PATH; skipping C compilation of pan.c.")
            return {"error": "gcc_not_found"}

        cwd = pml_file.parent.resolve()
        pml_name = pml_file.name

        def _run_cmd(cmd_args, desc):
            r = subprocess.run(cmd_args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            return r.returncode, r.stdout

        print(f"[spin]  Generating verifier from {pml_name} ...")
        rc, out = _run_cmd(["spin", "-a", pml_name], "spin -a")
        if rc != 0:
            print(f"[spin]  spin -a failed (exit {rc}):\n{out}")
            return {"error": "spin_a_failed", "raw": out}

        def _parse_pan_output(text: str) -> dict:
            errors = 0
            m_err = re.search(r"errors:\s*(\d+)", text)
            if m_err:
                errors = int(m_err.group(1))

            states = 0
            m_st = re.search(r"(\d+)\s+states,\s+stored", text)
            if m_st:
                states = int(m_st.group(1))

            depth = 0
            m_dp = re.search(r"depth reached\s+(\d+)", text)
            if m_dp:
                depth = int(m_dp.group(1))

            transitions = 0
            m_tr = re.search(r"(\d+)\s+transitions", text)
            if m_tr:
                transitions = int(m_tr.group(1))

            assertion_violated = errors > 0 and "assertion violated" in text.lower()
            deadlock = errors > 0 and "invalid end state" in text.lower()
            acceptance_cycle = errors > 0 and "acceptance cycle" in text.lower()
            depth_limit_hit = "depth limit reached" in text.lower()

            return {
                "errors": errors,
                "states": states,
                "transitions": transitions,
                "depth": depth,
                "assertion_violated": assertion_violated,
                "deadlock": deadlock,
                "acceptance_cycle": acceptance_cycle,
                "depth_limit_hit": depth_limit_hit,
                "raw": text,
            }

        print("[spin]  Compiling safety verifier (DSAFETY) ...")
        rc, out = _run_cmd(["gcc", "-DSAFETY", "-O2", "-o", "pan_safety", "pan.c"], "gcc DSAFETY")
        if rc != 0:
            print(f"[spin]  gcc pan_safety failed:\n{out}")
            return {"error": "gcc_safety_failed", "raw": out}

        print("[spin]  Running safety check (search depth=500000) ...")
        rc_s, out_s = _run_cmd(["./pan_safety", "-m500000"], "pan_safety")
        safety_data = _parse_pan_output(out_s)
        safety_data["exit_code"] = rc_s
        s_pass = (rc_s == 0 and safety_data["errors"] == 0)
        s_symbol = "✓ PASS" if s_pass else "✗ FAIL"
        print(f"[spin]  Safety  : {s_symbol}  (exit_code={rc_s}, errors={safety_data['errors']}, states={safety_data['states']}, depth={safety_data['depth']})")

        print("[spin]  Compiling liveness verifier ...")
        rc, out = _run_cmd(["gcc", "-O2", "-o", "pan_live", "pan.c"], "gcc pan_live")
        if rc != 0:
            print(f"[spin]  gcc pan_live failed:\n{out}")
            return {"error": "gcc_live_failed", "raw": out}

        print("[spin]  Running liveness check (-a, search depth=500000) ...")
        rc_l, out_l = _run_cmd(["./pan_live", "-a", "-m500000"], "pan_live")
        live_data = _parse_pan_output(out_l)
        live_data["exit_code"] = rc_l
        l_pass = (rc_l == 0 and live_data["errors"] == 0)
        l_symbol = "✓ PASS" if l_pass else "✗ FAIL"
        print(f"[spin]  Liveness: {l_symbol}  (exit_code={rc_l}, errors={live_data['errors']}, states={live_data['states']}, depth={live_data['depth']})")

        overall_pass = s_pass and l_pass
        report_data = {
            "pml": str(pml_file),
            "safety": safety_data,
            "liveness": live_data,
            "passed": overall_pass,
            "summary": "PASS — no errors found" if overall_pass else "FAIL — verification errors detected",
        }

        report_file = pml_file.with_name(pml_file.stem + "_spin_report.json")
        report_file.write_text(json.dumps(report_data, indent=2) + "\n")
        print(f"[gen_protocol]  wrote {report_file}")

        for f in [cwd / "pan.c", cwd / "pan.h", cwd / "pan.b", cwd / "pan.m", cwd / "pan.t",
                  cwd / "pan_safety", cwd / "pan_live", cwd / "_spin_nvr.tmp"]:
            try:
                if f.exists(): f.unlink()
            except OSError:
                pass

        res_str = "✓ PASS — PASS — no errors found" if overall_pass else "✗ FAIL — errors found"
        print(f"\n[spin]  Overall result: {res_str}\n")
        return report_data
