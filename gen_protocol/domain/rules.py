"""
Domain Rules and Pure Utility Functions.
"""

import hashlib
import json
import os
import re
import secrets
import struct
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from gen_protocol.domain.models import Field, Message, Protocol
from gen_protocol.domain.types import _C_RESERVED


def sanitize_proto_name(raw: str) -> str:
    """Produce a valid C identifier prefix from arbitrary input."""
    s = re.sub(r'[^A-Za-z0-9_]', '_', raw)
    s = re.sub(r'^[^A-Za-z]+', '', s)
    s = re.sub(r'_+', '_', s).strip('_')
    s = s.upper() or 'PROTO'
    if s.lower() in _C_RESERVED or s.startswith('_') or '__' in s:
        s = 'PROTO_' + s
    return s


def make_seed() -> str:
    """128-bit cryptographically strong seed, hex-encoded."""
    raw = secrets.token_bytes(16) + uuid.uuid4().bytes + struct.pack(">d", time.time())
    return hashlib.sha256(raw).hexdigest()[:32]


def calculate_magic(name: str, seed: str) -> int:
    """Deterministically compute 32-bit magic constant from name + seed with zero-byte patching."""
    h = hashlib.sha256(f"{name}:{seed}".encode()).digest()
    val = struct.unpack(">I", h[:4])[0]
    for i in range(4):
        if (val >> (i * 8)) & 0xFF == 0:
            val ^= (0xAB << (i * 8))
    return val & 0xFFFFFFFF


def field_wire_size(f: Field) -> int:
    """Calculate wire byte size for a Field."""
    sizes = {
        "uint8_t": 1, "int8_t": 1,
        "uint16_t": 2, "int16_t": 2,
        "uint32_t": 4, "int32_t": 4, "float": 4,
        "uint64_t": 8, "int64_t": 8, "double": 8,
    }
    unit = sizes.get(f.ctype, 1)
    if f.array_size is not None:
        return unit * f.array_size
    return unit


def msg_wire_size(m: Message) -> int:
    """Calculate wire byte size for a Message payload struct."""
    return sum(field_wire_size(f) for f in m.fields)


SEED_LOG = Path(__file__).resolve().parent.parent.parent / ".protocol_seeds.jsonl"


def log_seed(seed: str, proto_name: str) -> None:
    """Log seed to seed history log."""
    try:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "seed": seed, "name": proto_name}
        with SEED_LOG.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception as err:
        print(f"[gen_protocol]  warning: failed to write seed log: {err}")


def list_seeds() -> None:
    """List historical seeds."""
    if not SEED_LOG.exists():
        print("No seed log found.")
        return
    count = 0
    for line in SEED_LOG.read_text().splitlines():
        if not line.strip():
            continue
        try:
            d = json.loads(line)
            print(f"  {d['ts']}  seed={d['seed']}  name={d['name']}")
            count += 1
        except (json.JSONDecodeError, KeyError):
            continue
    if count == 0:
        print("No valid seed entries found.")
