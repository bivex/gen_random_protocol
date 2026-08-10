#!/usr/bin/env python3
"""
gen_protocol.py — Random C Protocol & IDL Compiler (DDD Hexagonal Architecture Entrypoint).
"""

import sys
from gen_protocol.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
