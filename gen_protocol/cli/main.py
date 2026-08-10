"""
CLI Command Line Presentation Adapter.
"""

import argparse
import sys
from pathlib import Path

from gen_protocol.application.compiler_service import ProtocolCompilerService
from gen_protocol.domain.rules import list_seeds
from gen_protocol.domain.types import PATTERNS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gen_protocol",
        description="Generate a unique random or compiled C binary protocol (VIQ Architecture).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 gen_protocol.py                         # fully random\n"
            "  python3 gen_protocol.py -n MY_PROTO -m 8 -f 5   # named, 8 msgs, max 5 fields\n"
            "  python3 gen_protocol.py -p rpc --spin --doc    # compile + Promela verification + doc\n"
            "  python3 gen_protocol.py --spec protocol.yaml   # compile from YAML IDL specification\n"
            "  python3 gen_protocol.py --seed 3e8c4ea8...     # reproduce past run\n"
        )
    )
    p.add_argument("-o", "--output",       metavar="DIR",  help="Output directory (default: ./out/<proto_name>/)")
    p.add_argument("-n", "--name",         metavar="NAME", help="Force protocol name prefix (sanitized)")
    p.add_argument("-m", "--messages",     type=int,       help="Number of message types (1..254, default: 4-16)")
    p.add_argument("-f", "--fields",       type=int,       help="Max fields per struct (1..64, default: 3-10)")
    p.add_argument("-p", "--pattern",      choices=["auto"] + PATTERNS, default="auto", help="Protocol pattern (default: auto)")
    p.add_argument("-c", "--multichain", "--chains", type=int, metavar="COUNT", help="Generate a MultiChain suite of COUNT interconnected protocols (1..32)")
    p.add_argument("--spec",               metavar="FILE", help="Compile protocol from YAML/JSON IDL specification file")
    p.add_argument("--export-spec",        action="store_true", help="Export declarative protocol.yaml IDL specification")
    p.add_argument("--doc",                action="store_true", help="Generate human-readable PROTOCOL_SPEC.md documentation")
    p.add_argument("--spin",               action="store_true", help="Generate Promela model and run SPIN verification")
    p.add_argument("--no-verify",          action="store_true", help="Generate Promela model file (.pml) but skip SPIN verification")
    p.add_argument("--no-impl",            action="store_true", help="Skip emitting .c implementation stub")
    p.add_argument("--seed",               metavar="HEX",  help="Reproduce a previous run (32 hex characters)")
    p.add_argument("--list-seeds",         action="store_true", help="Print all past seeds and exit")
    p.add_argument("--json",               action="store_true", help="Emit machine-readable manifest.json")
    p.add_argument("-v", "--verbose",      action="store_true", help="Print generated C header and implementation to stdout")
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_seeds:
        list_seeds()
        return 0

    if args.multichain is not None and not (1 <= args.multichain <= 32):
        parser.error("-c / --multichain must be between 1 and 32")

    if args.messages is not None and not (1 <= args.messages <= 254):
        parser.error("-m / --messages must be between 1 and 254")

    if args.fields is not None and not (1 <= args.fields <= 64):
        parser.error("-f / --fields must be between 1 and 64")

    if args.seed:
        args.seed = args.seed.strip().lower()
        if len(args.seed) != 32 or not all(c in "0123456789abcdef" for c in args.seed):
            parser.error("--seed must be a 32-character hex string")

    out_dir = Path(args.output) if args.output else None
    service = ProtocolCompilerService(out_dir=out_dir)

    try:
        if args.multichain:
            service.generate_multichain(
                args.multichain,
                seed_hex=args.seed,
                name_prefix=args.name,
                n_messages=args.messages,
                max_fields=args.fields,
                pattern=args.pattern,
                run_spin=args.spin,
                no_verify=args.no_verify,
                no_impl=args.no_impl,
                doc=args.doc,
                export_spec=args.export_spec,
                json_manifest=args.json,
                verbose=args.verbose
            )
        elif args.spec:
            service.compile_from_spec(
                Path(args.spec),
                run_spin=args.spin,
                no_verify=args.no_verify,
                no_impl=args.no_impl,
                doc=args.doc,
                export_spec=args.export_spec,
                json_manifest=args.json,
                verbose=args.verbose
            )
        else:
            service.generate_random(
                seed_hex=args.seed,
                name_hint=args.name,
                n_messages=args.messages,
                max_fields=args.fields,
                pattern=args.pattern,
                run_spin=args.spin,
                no_verify=args.no_verify,
                no_impl=args.no_impl,
                doc=args.doc,
                export_spec=args.export_spec,
                json_manifest=args.json,
                verbose=args.verbose
            )
        return 0
    except Exception as err:
        print(f"[gen_protocol]  error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
