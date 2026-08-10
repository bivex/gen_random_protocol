"""
Application Compiler Service orchestrating Domain Generator, Emitters, and Verifiers.
"""

from random import Random
from pathlib import Path
from typing import Optional

from gen_protocol.domain.generator import ProtocolGenerator
from gen_protocol.domain.models import Protocol
from gen_protocol.domain.rules import log_seed, make_seed
from gen_protocol.adapters.emitters.c_header import CHeaderEmitter
from gen_protocol.adapters.emitters.c_source import CSourceEmitter
from gen_protocol.adapters.emitters.promela import PromelaEmitter
from gen_protocol.adapters.emitters.markdown_doc import MarkdownDocEmitter
from gen_protocol.adapters.emitters.json_manifest import JsonManifestEmitter
from gen_protocol.adapters.emitters.yaml_spec import YamlSpecEmitter
from gen_protocol.adapters.idl.yaml_loader import YamlSpecLoader
from gen_protocol.adapters.verifiers.spin_verifier import SpinVerifier


class ProtocolCompilerService:
    """Application use-case service."""

    def __init__(self, out_dir: Optional[Path] = None) -> None:
        self.out_dir = out_dir

    def compile_from_spec(self, spec_path: Path, *,
                          run_spin: bool = False,
                          no_verify: bool = False,
                          no_impl: bool = False,
                          doc: bool = False,
                          export_spec: bool = False,
                          json_manifest: bool = False,
                          verbose: bool = False) -> Protocol:
        loader = YamlSpecLoader()
        proto = loader.load(spec_path)
        return self._emit_and_verify(
            proto,
            run_spin=run_spin,
            no_verify=no_verify,
            no_impl=no_impl,
            doc=doc,
            export_spec=export_spec,
            json_manifest=json_manifest,
            verbose=verbose
        )

    def generate_random(self, *,
                        seed_hex: Optional[str] = None,
                        name_hint: Optional[str] = None,
                        n_messages: Optional[int] = None,
                        max_fields: Optional[int] = None,
                        pattern: str = "auto",
                        run_spin: bool = False,
                        no_verify: bool = False,
                        no_impl: bool = False,
                        doc: bool = False,
                        export_spec: bool = False,
                        json_manifest: bool = False,
                        verbose: bool = False) -> Protocol:
        seed = seed_hex if seed_hex else make_seed()
        seed_bytes = bytes.fromhex(seed)
        seed_int = int.from_bytes(seed_bytes, "big")
        rng = Random(seed_int)

        gen = ProtocolGenerator(rng, seed)
        proto = gen.generate(
            name_hint=name_hint,
            n_messages=n_messages,
            max_fields=max_fields,
            pattern=pattern
        )

        log_seed(seed, proto.name)
        print(f"[gen_protocol]  seed = {seed}")

        return self._emit_and_verify(
            proto,
            run_spin=run_spin,
            no_verify=no_verify,
            no_impl=no_impl,
            doc=doc,
            export_spec=export_spec,
            json_manifest=json_manifest,
            verbose=verbose
        )

    def _emit_and_verify(self, proto: Protocol, *,
                         run_spin: bool = False,
                         no_verify: bool = False,
                         no_impl: bool = False,
                         doc: bool = False,
                         export_spec: bool = False,
                         json_manifest: bool = False,
                         verbose: bool = False) -> Protocol:
        n = proto.name.lower()
        out = self.out_dir if self.out_dir else Path(f"out/{n}")
        out.mkdir(parents=True, exist_ok=True)

        h_code = CHeaderEmitter(proto).emit()
        h_file = out / f"{n}.h"
        h_file.write_text(h_code)
        print(f"[gen_protocol]  wrote {h_file}")

        if not no_impl:
            c_code = CSourceEmitter(proto).emit()
            c_file = out / f"{n}.c"
            c_file.write_text(c_code)
            print(f"[gen_protocol]  wrote {c_file}")

        if json_manifest:
            m_code = JsonManifestEmitter(proto).emit()
            m_file = out / f"{n}_manifest.json"
            m_file.write_text(m_code)
            print(f"[gen_protocol]  wrote {m_file}")

        if export_spec:
            y_code = YamlSpecEmitter(proto).emit()
            y_file = out / "protocol.yaml"
            y_file.write_text(y_code)
            print(f"[gen_protocol]  wrote {y_file}")

        if doc:
            d_code = MarkdownDocEmitter(proto).emit()
            d_file = out / "PROTOCOL_SPEC.md"
            d_file.write_text(d_code)
            print(f"[gen_protocol]  wrote {d_file}")

        pml_file = None
        if run_spin or no_verify:
            pml_code = PromelaEmitter(proto).emit()
            pml_file = out / f"{n}.pml"
            pml_file.write_text(pml_code)
            print(f"[gen_protocol]  wrote {pml_file}")

            if run_spin and not no_verify:
                print()
                SpinVerifier().verify(pml_file)

        if verbose:
            print("\n" + "="*80)
            print(h_code)
            if not no_impl:
                print("="*80)
                print(c_code)

        print(f"\n[gen_protocol]  Protocol : {proto.name}  v{proto.version_major}.{proto.version_minor}.{proto.version_patch}")
        print(f"                Pattern  : {proto.pattern.upper()}")
        print(f"                Magic    : 0x{proto.magic:08X}")
        print(f"                Endian   : {proto.endian}-endian")
        print(f"                Messages : {len(proto.messages)}")
        print(f"                MaxPay   : {proto.max_payload_size} bytes")
        print(f"                Verified : {'PASS' if run_spin and not no_verify else 'N/A'}\n")
        print(f"  To reproduce: python gen_protocol.py --seed {proto.seed}\n")

        return proto
