#!/usr/bin/env python3
"""
gen_protocol.py — Random C Protocol VIQ Generator
==================================================
Generates 100% unique C protocol headers & stubs per invocation.

Uniqueness guarantees
---------------------
  * UUID4 entropy seed injected at startup
  * Cryptographic salt (secrets module) mixed into every name/magic
  * Per-field type/layout randomization
  * Collision-resistant magic numbers (32-bit CRC over seed + timestamp)

Usage
-----
  python gen_protocol.py [OPTIONS]

  -o, --output DIR        Write files to DIR (default: ./out/<proto_name>/)
  -n, --name NAME         Force protocol name prefix (default: random)
  -m, --messages N        Number of message types  (default: 4-16)
  -f, --fields N          Max fields per struct     (default: 3-10)
  -p, --pattern PATTERN   Protocol pattern: auto|reqrsp|stream|pubsub|rpc|fsm
  --no-impl               Skip .c stub generation
  --seed HEX              Reproduce a previous run (hex seed string)
  --list-seeds            Print seeds of past runs from seed log
  --json                  Also emit machine-readable protocol manifest
  -v, --verbose           Print generated code to stdout as well
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re as _re
import secrets
import struct
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from random import Random
from typing import Any

# ---------------------------------------------------------------------------
# C identifier safety
# ---------------------------------------------------------------------------

_C_RESERVED = frozenset({
    'auto','break','case','char','const','continue','default','do',
    'double','else','enum','extern','float','for','goto','if','inline',
    'int','long','register','restrict','return','short','signed','sizeof',
    'static','struct','switch','typedef','union','unsigned','void',
    'volatile','while',
    # C99/C11 keywords
    '_bool','_complex','_imaginary','_alignas','_alignof','_atomic',
    '_generic','_noreturn','_static_assert','_thread_local',
    # common typedefs that clash
    'bool','true','false','size_t','ptrdiff_t','intptr_t','uintptr_t',
})

def _sanitize_proto_name(raw: str) -> str:
    """
    Produce a valid C identifier prefix from arbitrary user input.

    Rules applied
    -------------
    1. Replace every character that is not [A-Za-z0-9_] with '_'.
    2. Strip leading characters that are not [A-Za-z_]  (C idents cannot
       start with a digit).
    3. Collapse runs of underscores to a single '_' and strip trailing '_'.
    4. Uppercase the result.
    5. If the result is a C reserved word (case-insensitive), prefix 'PROTO_'.
    6. Fall back to 'PROTO' if the result is empty after all steps.
    """
    s = _re.sub(r'[^A-Za-z0-9_]', '_', raw)
    s = _re.sub(r'^[^A-Za-z_]+', '', s)   # strip leading non-ident chars
    s = _re.sub(r'_+', '_', s).strip('_') # collapse/strip underscores
    s = s.upper() or 'PROTO'
    if s.lower() in _C_RESERVED:
        s = 'PROTO_' + s
    return s

# ---------------------------------------------------------------------------
# Entropy / seed management
# ---------------------------------------------------------------------------

SEED_LOG = Path(__file__).parent / ".protocol_seeds.jsonl"


def _make_seed() -> str:
    """128-bit cryptographically strong seed, hex-encoded."""
    raw = secrets.token_bytes(16) + uuid.uuid4().bytes + struct.pack(">d", time.time())
    return hashlib.sha256(raw).hexdigest()[:32]


def _log_seed(seed: str, proto_name: str) -> None:
    try:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "seed": seed, "name": proto_name}
        with SEED_LOG.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception as err:
        print(f"[gen_protocol]  warning: failed to write seed log: {err}")


def _list_seeds() -> None:
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



# ---------------------------------------------------------------------------
# Vocabulary banks
# ---------------------------------------------------------------------------

PROTO_NOUNS = [
    "NEXUS", "FLUX", "VORTEX", "CIPHER", "AXIOM", "RELAY", "VECTOR", "CONDUIT",
    "HERALD", "STRATUM", "BEACON", "AETHER", "LATTICE", "PULSE", "CORONA", "APEX",
    "ZENITH", "PRISM", "QUORUM", "HELIOS", "SIGMA", "DELTA", "OMEGA", "ECHO",
    "TERRA", "SPECTRA", "RIFT", "NOVA", "LYNX", "COBALT", "TITAN", "FERRO",
    "QUASAR", "HYDRA", "PEGASUS", "ORCA", "ARGON", "NEON", "CHROME", "BASALT",
    "ASTRA", "SOLAR", "LUNAR", "POLAR", "NIMBUS", "KINETIC", "TEMPEST", "ORION",
    "VALKYRIE", "PHOENIX", "STARDUST", "NEBULA", "AURORA", "HALO", "RADIAN", "TENSOR",
]

PROTO_SUFFIXES = [
    "LINK", "NET", "BUS", "WIRE", "GATE", "CHAN", "SYNC", "FLOW", "HUB", "MUX",
    "CAST", "MESH", "EDGE", "NODE", "CORE", "SPAN", "PATH", "RACK", "PIPE", "SLOT",
    "GRID", "RING", "FABRIC", "BRIDGE", "TUNNEL", "PORTAL", "SOCKET", "VALVE", "PORT",
]


FIELD_ADJECTIVES = [
    "src", "dst", "seq", "ack", "flags", "status", "ctrl", "cfg", "data", "payload",
    "len", "checksum", "version", "type", "subtype", "group", "session", "stream",
    "priority", "ttl", "hop", "window", "offset", "tag", "id", "epoch", "nonce",
    "opcode", "reason", "code", "mask", "mode", "channel", "port", "addr",
    "timestamp", "signature", "key", "token", "reserved", "padding", "crc", "hash",
]

MSG_VERBS = [
    "CONNECT", "ACCEPT", "REJECT", "OPEN", "CLOSE", "PING", "PONG", "SYNC", "RESET",
    "SUBSCRIBE", "UNSUBSCRIBE", "PUBLISH", "REQUEST", "RESPONSE", "ACK", "NACK",
    "PUSH", "PULL", "FETCH", "COMMIT", "ROLLBACK", "HEARTBEAT", "HELLO", "BYE",
    "AUTH", "CHALLENGE", "GRANT", "REVOKE", "REGISTER", "DEREGISTER", "QUERY",
    "UPDATE", "DELETE", "INSERT", "NOTIFY", "ALERT", "ERROR", "STATUS", "METRICS",
    "FLOW_CTRL", "WINDOW_UPDATE", "KEEPALIVE", "PROBE", "DISCOVER", "ANNOUNCE",
    "HANDSHAKE", "NEGOTIATE", "CONFIGURE", "TRANSFER", "COMPLETE", "ABORT",
]

C_TYPES = {
    "u8":   ("uint8_t",  1),
    "u16":  ("uint16_t", 2),
    "u32":  ("uint32_t", 4),
    "u64":  ("uint64_t", 8),
    "i8":   ("int8_t",   1),
    "i16":  ("int16_t",  2),
    "i32":  ("int32_t",  4),
    "i64":  ("int64_t",  8),
    "f32":  ("float",    4),
    "f64":  ("double",   8),
    "bool": ("uint8_t",  1),  # Explicit 1-octet boolean wire type (0=false, 1=true)
}

C_TYPE_KEYS     = list(C_TYPES.keys())
# Smaller types are more common in real protocol fields
C_TYPE_WEIGHTS  = [12, 10, 8, 4, 6, 5, 4, 2, 1, 1, 3]

PATTERNS = ["reqrsp", "stream", "pubsub", "rpc", "fsm"]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Field:
    name:       str
    ctype:      str
    bits:       "int | None"       # None = normal field, int = bitfield width
    array_size: "int | None"       # None = scalar, int = fixed array
    comment:    str


@dataclass
class Message:
    name:        str      # e.g. MSG_CONNECT
    opcode:      int      # 0x01-0xFE unique within protocol
    fields:      "list[Field]"
    direction:   str      # "C->S" | "S->C" | "BIDI"
    description: str


@dataclass
class Enum:
    name:    str
    members: "list[tuple[str, int]]"  # (name, value)


@dataclass
class Protocol:
    name:               str
    version_major:      int
    version_minor:      int
    version_patch:      int
    magic:              int       # 32-bit
    pattern:            str
    seed:               str
    messages:           "list[Message]"
    enums:              "list[Enum]"
    header_struct_name: str
    max_payload_size:   int
    endian:             str       # "little" | "big"
    description:        str


# ---------------------------------------------------------------------------
# Generator core
# ---------------------------------------------------------------------------

class ProtocolGenerator:
    def __init__(self, rng: Random, seed: str) -> None:
        self.rng  = rng
        self.seed = seed

    # -- helpers -------------------------------------------------------------

    def _pick(self, seq):
        return self.rng.choice(seq)

    def _weighted_pick(self, seq, weights):
        return self.rng.choices(seq, weights=weights, k=1)[0]

    def _unique_name(self, base: str, used: set) -> str:
        name   = base
        suffix = 0
        while name in used:
            suffix += 1
            name = f"{base}_{suffix}"
        used.add(name)
        return name

    # -- name generation -----------------------------------------------------

    def proto_name(self, forced: "str | None") -> str:
        if forced:
            clean = _sanitize_proto_name(forced)
            if clean != forced.upper().replace(' ', '_'):
                print(f"[gen_protocol]  name sanitized: {forced!r} → {clean!r}")
            return clean
        noun   = self._pick(PROTO_NOUNS)
        suffix = self._pick(PROTO_SUFFIXES)
        return f"{noun}_{suffix}"

    def _magic(self, name: str) -> int:
        h   = hashlib.sha256(f"{name}:{self.seed}".encode()).digest()
        val = struct.unpack(">I", h[:4])[0]
        for i in range(4):
            if (val >> (i * 8)) & 0xFF == 0:
                val ^= (0xAB << (i * 8))
        return val & 0xFFFFFFFF

    # -- field generation ----------------------------------------------------

    def _gen_field(self, used_names: set,
                   allow_array: bool = True,
                   allow_bitfield: bool = True) -> Field:
        adj   = self._pick(FIELD_ADJECTIVES)
        name  = self._unique_name(adj, used_names)
        tkey  = self._weighted_pick(C_TYPE_KEYS, C_TYPE_WEIGHTS)
        ctype, _ = C_TYPES[tkey]

        bits       = None
        array_size = None

        if allow_bitfield and tkey.startswith("u") and self.rng.random() < 0.18:
            bits = self.rng.choice([1, 2, 3, 4])
        elif allow_array and tkey == "u8" and self.rng.random() < 0.22:
            array_size = self.rng.choice([4, 8, 16, 32, 64, 128, 256])

        comment = self._field_comment(name, tkey)
        return Field(name=name, ctype=ctype, bits=bits,
                     array_size=array_size, comment=comment)

    def _field_comment(self, name: str, tkey: str) -> str:
        opts = [
            f"Protocol {name} field",
            f"Identifies the {name} attribute",
            f"Carries {name} value ({tkey})",
            f"Encodes {name} state",
            f"Raw {name} — see spec §{self.rng.randint(2,9)}.{self.rng.randint(1,12)}",
        ]
        return self._pick(opts)

    def _gen_fields(self, n: int) -> "list[Field]":
        used: set = set()
        return [self._gen_field(used) for _ in range(n)]

    # -- enum generation -----------------------------------------------------

    def _gen_enum(self, proto_name: str, tag: str,
                  member_names: "list[str]") -> Enum:
        enum_name = f"{proto_name}_{tag}_t"
        seen:  set = set()
        vals: "list[tuple[str,int]]" = []
        counter = 0
        for m in member_names:
            key = f"{proto_name}_{tag}_{m}"
            if key in seen:
                continue
            seen.add(key)
            vals.append((key, counter))
            counter += 1
        return Enum(name=enum_name, members=vals)

    # -- message generation --------------------------------------------------

    def _gen_message(self, proto_name: str,
                     used_ops: set, used_names: set,
                     max_fields: int, pattern: str) -> Message:
        if len(used_ops) >= 254:
            raise ValueError("Cannot generate more than 254 unique opcodes per protocol")

        op = self.rng.randint(0x01, 0xFE)
        while op in used_ops:
            op = self.rng.randint(0x01, 0xFE)
        used_ops.add(op)

        verb = self._pick(MSG_VERBS)
        name = self._unique_name(f"{proto_name}_MSG_{verb}", used_names)

        # Account for injected semantic fields so total field count respects max_fields
        injected_count = 2 if pattern in ("rpc", "stream") else (1 if pattern in ("reqrsp", "pubsub", "fsm") else 0)
        n_random = max(1, max_fields - injected_count)
        fields   = self._gen_fields(n_random)

        # Pattern-specific semantic field injection
        if pattern == "reqrsp":
            direction = "C->S" if ("REQUEST" in verb or "QUERY" in verb or "FETCH" in verb) else ("S->C" if "RESPONSE" in verb or "ACK" in verb else self._pick(["C->S", "S->C", "BIDI"]))
            fields.insert(0, Field(name="request_id", ctype="uint32_t", bits=None, array_size=None, comment="Correlation ID matching request to response"))
        elif pattern == "pubsub":
            direction = "C->S" if ("SUBSCRIBE" in verb or "REGISTER" in verb) else ("S->C" if "PUBLISH" in verb or "NOTIFY" in verb else self._pick(["C->S", "S->C", "BIDI"]))
            fields.insert(0, Field(name="topic_id", ctype="uint32_t", bits=None, array_size=None, comment="PubSub channel or topic identifier"))
        elif pattern == "rpc":
            direction = "C->S" if ("CALL" in verb or "REQUEST" in verb or "INVOKE" in verb) else ("S->C" if "RETURN" in verb or "RESPONSE" in verb else self._pick(["C->S", "S->C", "BIDI"]))
            fields.insert(0, Field(name="method_id", ctype="uint16_t", bits=None, array_size=None, comment="RPC procedure method index"))
            fields.insert(1, Field(name="call_id", ctype="uint32_t", bits=None, array_size=None, comment="RPC invocation sequence ID"))
        elif pattern == "stream":
            direction = "C->S" if "PUSH" in verb or "TRANSFER" in verb else self._pick(["C->S", "S->C", "BIDI"])
            fields.insert(0, Field(name="stream_id", ctype="uint32_t", bits=None, array_size=None, comment="Stream multiplexing identifier"))
            fields.insert(1, Field(name="chunk_offset", ctype="uint64_t", bits=None, array_size=None, comment="Byte offset within stream"))
        elif pattern == "fsm":
            direction = self._pick(["C->S", "S->C", "BIDI"])
            fields.insert(0, Field(name="state_id", ctype="uint8_t", bits=None, array_size=None, comment="Current state machine phase ID"))
        else:
            direction = self._pick(["C->S", "S->C", "BIDI"])

        desc_tmpl = [
            f"Initiates a {verb.lower()} transaction",
            f"Signals {verb.lower()} event to peer",
            f"Carries {verb.lower()} payload",
            f"Requests {verb.lower()} acknowledgement",
            f"Conveys {verb.lower()} state change",
        ]
        desc = self._pick(desc_tmpl)
        return Message(name=name, opcode=op, fields=fields,
                       direction=direction, description=desc)



    # -- protocol assembly ---------------------------------------------------

    def generate(self, *,
                 name_hint: "str | None" = None,
                 n_messages: "int | None" = None,
                 max_fields: "int | None" = None,
                 pattern: str = "auto") -> Protocol:

        if pattern == "auto":
            pattern = self._pick(PATTERNS)

        proto_name = self.proto_name(name_hint)
        magic      = self._magic(proto_name)

        ver_major = self.rng.randint(1, 5)
        ver_minor = self.rng.randint(0, 15)
        ver_patch = self.rng.randint(0, 99)

        endian = self._pick(["little", "big"])

        nm = n_messages if n_messages else self.rng.randint(4, 16)
        mf = max_fields  if max_fields  else self.rng.randint(3, 10)

        max_payload = self.rng.choice([128, 256, 512, 1024, 2048, 4096, 8192])

        used_ops:   set = set()
        used_names: set = set()
        messages = []
        for _ in range(nm):
            msg = self._gen_message(proto_name, used_ops, used_names, mf, pattern)
            messages.append(msg)

        dir_enum = self._gen_enum(proto_name, "DIRECTION",
                                  ["CLIENT_TO_SERVER", "SERVER_TO_CLIENT",
                                   "BROADCAST", "MULTICAST", "LOOPBACK"])
        err_enum = self._gen_enum(proto_name, "ERR",
                                  ["OK", "TIMEOUT", "INVALID_OPCODE", "AUTH_FAIL",
                                   "PAYLOAD_TOO_LARGE", "CHECKSUM_MISMATCH",
                                   "UNSUPPORTED_VERSION", "RESOURCE_EXHAUSTED",
                                   "PROTOCOL_VIOLATION", "INTERNAL_ERROR"])
        state_members = (
            ["IDLE", "CONNECTING", "CONNECTED", "NEGOTIATING",
             "TRANSFERRING", "DRAINING", "CLOSING", "CLOSED", "ERROR"]
            if pattern == "fsm" else
            ["INIT", "READY", "BUSY", "DONE", "FAILED"]
        )
        state_enum = self._gen_enum(proto_name, "STATE", state_members)

        desc_map = {
            "reqrsp": "Request/response protocol — client sends requests, server replies",
            "stream": "Streaming protocol — continuous unidirectional data flow",
            "pubsub": "Publish/subscribe protocol — broker-mediated topic dispatch",
            "rpc":    "Remote Procedure Call protocol — typed method invocation",
            "fsm":    "State-machine protocol — strict phase transitions enforced",
        }

        return Protocol(
            name               = proto_name,
            version_major      = ver_major,
            version_minor      = ver_minor,
            version_patch      = ver_patch,
            magic              = magic,
            pattern            = pattern,
            seed               = self.seed,
            messages           = messages,
            enums              = [dir_enum, err_enum, state_enum],
            header_struct_name = f"{proto_name.lower()}_hdr_t",
            max_payload_size   = max_payload,
            endian             = endian,
            description        = desc_map[pattern],
        )


# ---------------------------------------------------------------------------
# C header emitter
# ---------------------------------------------------------------------------

class CHeaderEmitter:
    def __init__(self, proto: Protocol) -> None:
        self.p = proto

    def _banner(self) -> str:
        p  = self.p
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return (
            f"/*\n"
            f" * {'='*73}\n"
            f" *  Protocol  : {p.name}  v{p.version_major}.{p.version_minor}.{p.version_patch}\n"
            f" *  Pattern   : {p.pattern.upper()}\n"
            f" *  Endian    : {p.endian}-endian\n"
            f" *  Magic     : 0x{p.magic:08X}\n"
            f" *  MaxPayload: {p.max_payload_size} bytes\n"
            f" *  Generated : {ts}\n"
            f" *  Seed      : {p.seed}\n"
            f" *\n"
            f" *  {p.description}\n"
            f" *\n"
            f" *  AUTO-GENERATED — DO NOT EDIT BY HAND\n"
            f" * {'='*73}\n"
            f" */\n"
        )

    def _macros(self) -> str:
        p = self.p
        # P0-FIX: endian flag used by TO_WIRE/FROM_WIRE macros in the .c file
        endian_define = (
            f"#define {p.name}_WIRE_BIG_ENDIAN  1U"
            if p.endian == "big" else
            f"/* {p.name}_WIRE_BIG_ENDIAN not defined — wire is little-endian */"
        )
        lines = [
            "/* === Protocol constants === */",
            f"#define {p.name}_MAGIC           0x{p.magic:08X}UL",
            f"#define {p.name}_VERSION_MAJOR   {p.version_major}U",
            f"#define {p.name}_VERSION_MINOR   {p.version_minor}U",
            f"#define {p.name}_VERSION_PATCH   {p.version_patch}U",
            f"#define {p.name}_VERSION         "
            f"(({p.version_major}U<<16)|({p.version_minor}U<<8)|{p.version_patch}U)",
            f"#define {p.name}_MAX_PAYLOAD     {p.max_payload_size}U",
            f"#define {p.name}_HDR_SIZE        sizeof({p.header_struct_name})",
            "",
            f"/* === Wire byte order: {p.endian}-endian === */",
            endian_define,
            "",
            "/* Portable byte-swap — no system headers needed */",
            "#ifndef _PROTO_BSWAP16",
            "#  define _PROTO_BSWAP16(x) \\",
            "        ((uint16_t)(((uint16_t)(x) >> 8U) | ((uint16_t)(x) << 8U)))",
            "#endif",
            "#ifndef _PROTO_BSWAP32",
            "#  define _PROTO_BSWAP32(x) \\",
            "        (((uint32_t)(x) >> 24U)               | \\",
            "         (((uint32_t)(x) >> 8U)  & 0x0000FF00UL) | \\",
            "         (((uint32_t)(x) << 8U)  & 0x00FF0000UL) | \\",
            "         ((uint32_t)(x) << 24U))",
            "#endif",
            "#ifndef _PROTO_BSWAP64",
            "#  define _PROTO_BSWAP64(x) \\",
            "        (((uint64_t)(x) >> 56U)                        | \\",
            "         (((uint64_t)(x) >> 40U) & 0x000000000000FF00ULL) | \\",
            "         (((uint64_t)(x) >> 24U) & 0x0000000000FF0000ULL) | \\",
            "         (((uint64_t)(x) >> 8U)  & 0x00000000FF000000ULL) | \\",
            "         (((uint64_t)(x) << 8U)  & 0x000000FF00000000ULL) | \\",
            "         (((uint64_t)(x) << 24U) & 0x0000FF0000000000ULL) | \\",
            "         (((uint64_t)(x) << 40U) & 0x00FF000000000000ULL) | \\",
            "         ((uint64_t)(x) << 56U))",
            "#endif",
            "",
            "/* Detect host byte order at compile time */",
            "#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__",
            "#  define _PROTO_HOST_IS_BE 1",
            "#else",
            "#  define _PROTO_HOST_IS_BE 0",
            "#endif",
            "",
            "/* Portable IEEE-754 float/double conversion (no undefined behavior) */",
            "static inline uint32_t _proto_f32_to_u32(float f) { uint32_t u; memcpy(&u, &f, sizeof(u)); return u; }",
            "static inline float    _proto_u32_to_f32(uint32_t u) { float f; memcpy(&f, &u, sizeof(f)); return f; }",
            "static inline uint64_t _proto_f64_to_u64(double d) { uint64_t u; memcpy(&u, &d, sizeof(u)); return u; }",
            "static inline double   _proto_u64_to_f64(uint64_t u) { double d; memcpy(&d, &u, sizeof(d)); return d; }",
            "",
            f"/* {p.name}: convert multi-byte fields between host and {p.endian}-endian wire order */",
        ]
        if p.endian == "big":
            lines += [
                f"#define {p.name}_TO_WIRE16(x)   (_PROTO_HOST_IS_BE ? (uint16_t)(x) : _PROTO_BSWAP16(x))",
                f"#define {p.name}_FROM_WIRE16(x)  {p.name}_TO_WIRE16(x)",
                f"#define {p.name}_TO_WIRE32(x)   (_PROTO_HOST_IS_BE ? (uint32_t)(x) : _PROTO_BSWAP32(x))",
                f"#define {p.name}_FROM_WIRE32(x)  {p.name}_TO_WIRE32(x)",
                f"#define {p.name}_TO_WIRE64(x)   (_PROTO_HOST_IS_BE ? (uint64_t)(x) : _PROTO_BSWAP64(x))",
                f"#define {p.name}_FROM_WIRE64(x)  {p.name}_TO_WIRE64(x)",
            ]
        else:
            lines += [
                f"#define {p.name}_TO_WIRE16(x)   (_PROTO_HOST_IS_BE ? _PROTO_BSWAP16(x) : (uint16_t)(x))",
                f"#define {p.name}_FROM_WIRE16(x)  {p.name}_TO_WIRE16(x)",
                f"#define {p.name}_TO_WIRE32(x)   (_PROTO_HOST_IS_BE ? _PROTO_BSWAP32(x) : (uint32_t)(x))",
                f"#define {p.name}_FROM_WIRE32(x)  {p.name}_TO_WIRE32(x)",
                f"#define {p.name}_TO_WIRE64(x)   (_PROTO_HOST_IS_BE ? _PROTO_BSWAP64(x) : (uint64_t)(x))",
                f"#define {p.name}_FROM_WIRE64(x)  {p.name}_TO_WIRE64(x)",
            ]

        lines += [
            "",
            "/* === Opcode definitions === */",
        ]
        for msg in p.messages:
            lines.append(
                f"#define {msg.name:<54} 0x{msg.opcode:02X}U"
                f"  /* {msg.direction} — {msg.description} */"
            )
        return "\n".join(lines)

    def _emit_enum(self, e: Enum) -> str:
        lines = [f"typedef enum {{"]
        for name, val in e.members:
            lines.append(f"    {name} = {val},")
        lines.append(f"}} {e.name};")
        return "\n".join(lines)

    def _emit_field(self, f: Field) -> str:
        # P0-FIX: C bitfields (': N') are non-portable for wire protocols —
        # bit ordering and padding are implementation-defined (C11 §6.7.2.1).
        # Promote every bitfield to its natural full-width type and generate
        # explicit GET/SET accessor macros instead (see _bitfield_accessors).
        if f.bits is not None:
            mask = (1 << f.bits) - 1
            return (
                f"    {f.ctype:<12} {f.name};  "
                f"/* [bits {f.bits-1}:0] active ({f.bits}-bit field) — {f.comment} */"
            )
        elif f.array_size is not None:
            return f"    {f.ctype:<12} {f.name}[{f.array_size}];  /* {f.comment} */"
        else:
            return f"    {f.ctype:<12} {f.name};  /* {f.comment} */"

    def _bitfield_accessors(self, msg: Message) -> str:
        """Emit portable GET/SET macros for fields that were originally bitfields."""
        lines = []
        for f in msg.fields:
            if f.bits is None:
                continue
            mask     = (1 << f.bits) - 1
            mask_hex = f"0x{mask:02X}U" if mask <= 0xFF else f"0x{mask:04X}U"
            pname    = self.p.name
            fname    = f.name.upper()
            mname    = msg.name  # already upper
            lines += [
                f"/* Portable {f.bits}-bit accessor for {msg.name.lower()}_t.{f.name} */",
                f"#define {pname}_GET_{mname}_{fname}(s)    ((s)->{f.name} & {mask_hex})",
                f"#define {pname}_SET_{mname}_{fname}(s, v) \\",
                f"    ((s)->{f.name} = (uint8_t)(((s)->{f.name} & ~{mask_hex}) "
                f"| ((uint8_t)(v) & {mask_hex})))",
            ]
        return "\n".join(lines)

    def _common_hdr_struct(self) -> str:
        p = self.p
        return "\n".join([
            f"/* Common wire header — prepended to every {p.name} frame */",
            f"/* Multi-byte fields are in {p.endian}-endian wire order.  "
            f"Call {p.name.lower()}_hdr_encode() before send, _hdr_decode() after recv. */",
            f"typedef struct __attribute__((packed)) {{",
            f"    uint32_t     magic;        /* Must equal {p.name}_MAGIC (wire order) */",
            f"    uint32_t     version;      /* Encoded {p.version_major}.{p.version_minor}.{p.version_patch} (wire order) */",
            f"    uint8_t      opcode;       /* One of {p.name}_MSG_* */",
            f"    uint8_t      flags;        /* Protocol-defined flag bits */",
            f"    uint16_t     payload_len;  /* Payload byte length (wire order) */",
            f"    uint32_t     seq;          /* Monotonic sequence number (wire order) */",
            f"    uint32_t     session_id;   /* Session identifier (wire order) */",
            f"    uint32_t     crc32;        /* CRC-32/ISO-HDLC of hdr(crc=0)+payload (wire order) */",
            f"}} {p.header_struct_name};",
        ])

    def _msg_struct(self, msg: Message) -> str:
        lines = [
            f"/* {msg.name} payload  (opcode=0x{msg.opcode:02X}, {msg.direction}) */",
            f"/* {msg.description} */",
            f"typedef struct __attribute__((packed)) {{",
        ]
        for f in msg.fields:
            lines.append(self._emit_field(f))
        lines.append(f"}} {msg.name.lower()}_t;")
        # Append bitfield accessors only if any field needs them
        accessors = self._bitfield_accessors(msg)
        if accessors:
            lines += ["", accessors]
        return "\n".join(lines)

    def _prototypes(self) -> str:
        p = self.p
        n = p.name.lower()
        return "\n".join([
            "/* === API prototypes === */",
            "",
            "/**",
            f" * @brief  Initialise a {p.header_struct_name} for the given opcode.",
            f" * @note   Fields are set in HOST byte order; call {n}_hdr_encode()",
            f" *         before writing to the wire.",
            f" * @param  hdr      Header to initialise.",
            f" * @param  opcode   One of {p.name}_MSG_* constants.",
            f" * @param  sess_id  Session identifier.",
            f" * @param  seq      Monotonic sequence counter for this session/message.",
            f" * @param  pay_len  Payload length in bytes.",
            " */",
            f"void {n}_hdr_init({p.header_struct_name} *hdr, uint8_t opcode,",
            f"                  uint32_t sess_id, uint32_t seq, uint16_t pay_len);",

            "",
            "/**",
            f" * @brief  Compute the CRC-32/ISO-HDLC over a complete {p.name} frame.",
            f" * @note   Call this AFTER filling the payload and BEFORE {n}_hdr_encode().",
            f" *         Store the result in hdr->crc32, then call {n}_hdr_encode().",
            f" * @param  hdr     Pointer to header (crc32 field is ignored / treated as 0).",
            f" * @param  payload Pointer to payload bytes (may be NULL if pay_len == 0).",
            f" * @param  pay_len Payload length in bytes.",
            f" * @return CRC-32 of (zeroed-crc32 header) || payload.",
            " */",
            f"uint32_t {n}_frame_crc(const {p.header_struct_name} *hdr,",
            f"                       const void *payload, size_t pay_len);",
            "",
            "/**",
            f" * @brief  Validate a received (already-decoded) {p.header_struct_name}.",
            f" * @note   Call {n}_hdr_decode() before this function.",
            " * @return 0 on success, negative errno-style code on failure.",
            " */",
            f"int  {n}_hdr_validate(const {p.header_struct_name} *hdr,",
            f"                      const void *payload, size_t pay_len);",
            "",
            "/**",
            f" * @brief  Convert header multi-byte fields from host to {p.endian}-endian wire order.",
            f" * @note   Call after {n}_hdr_init() / setting crc32, before sending.",
            " */",
            f"void {n}_hdr_encode({p.header_struct_name} *hdr);",
            "",
            "/**",
            f" * @brief  Convert header multi-byte fields from {p.endian}-endian wire to host order.",
            f" * @note   Call immediately after receiving raw bytes, before inspecting fields.",
            " */",
            f"void {n}_hdr_decode({p.header_struct_name} *hdr);",
            "",
            "/* === Per-message payload wire serialization prototypes === */",
            "\n".join([
                f"void {msg.name.lower()}_encode({msg.name.lower()}_t *msg);\n"
                f"void {msg.name.lower()}_decode({msg.name.lower()}_t *msg);"
                for msg in p.messages
            ]),
            "",
            "/**",
            " * @brief  Compute CRC-32/ISO-HDLC over [data, data+len).",
            " */",
            f"uint32_t {n}_crc32(const void *data, size_t len);",
            "",
            "/**",
            " * @brief  Return a human-readable opcode string.",
            " */",
            f"const char *{n}_opcode_str(uint8_t opcode);",
        ])


    def emit(self) -> str:
        guard = f"{self.p.name}_H"
        parts = [
            self._banner(),
            f"#ifndef {guard}",
            f"#define {guard}",
            "",
            "#include <stdint.h>",
            "#include <stdbool.h>",
            "#include <stddef.h>",
            "#include <string.h>",

            "",
            "#ifdef __cplusplus",
            'extern "C" {',
            "#endif",
            "",
            self._macros(),
            "",
            "/* === Enumerations === */",
        ]
        for e in self.p.enums:
            parts.append(self._emit_enum(e))
            parts.append("")
        parts += [
            "/* === Wire structures === */",
            self._common_hdr_struct(),
            "",
        ]
        for msg in self.p.messages:
            parts.append(self._msg_struct(msg))
            parts.append("")
        parts += [
            self._prototypes(),
            "",
            "#ifdef __cplusplus",
            "}",
            "#endif",
            "",
            f"#endif /* {guard} */",
        ]
        return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# C implementation stub emitter
# ---------------------------------------------------------------------------

class CImplEmitter:
    def __init__(self, proto: Protocol, header_filename: str) -> None:
        self.p  = proto
        self.hf = header_filename

    def _crc32_table(self) -> str:
        poly    = 0xEDB88320
        entries = []
        for i in range(256):
            crc = i
            for _ in range(8):
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
            entries.append(f"0x{crc:08X}UL")
        rows = ["    " + ", ".join(entries[r:r+8]) + "," for r in range(0, 256, 8)]
        return "static const uint32_t _crc32_table[256] = {\n" + "\n".join(rows) + "\n};\n"

    def _opcode_map(self) -> str:
        p = self.p
        n = p.name.lower()
        lines = [
            f"const char *{n}_opcode_str(uint8_t opcode) {{",
            f"    switch (opcode) {{",
        ]
        for msg in p.messages:
            lines.append(f'        case {msg.name}: return "{msg.name}";')
        lines += [
            '        default:         return "<UNKNOWN_OPCODE>";',
            "    }",
            "}",
        ]
        return "\n".join(lines)

    def emit(self) -> str:
        p  = self.p
        n  = p.name.lower()
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return "\n".join([
            f"/* {p.name} — generated implementation stub",
            f" * Generated : {ts}",
            f" * Seed      : {p.seed}",
            f" * AUTO-GENERATED — DO NOT EDIT BY HAND",
            f" */",
            f'#include "{self.hf}"',
            "#include <string.h>",
            "",
            self._crc32_table(),
            # ------------------------------------------------------------------
            # P0-FIX 1: _crc32_update lets us chain header + payload in one pass
            # without restarting (XOR of two independent CRCs is wrong).
            # ------------------------------------------------------------------
            f"/* Internal: continue a CRC-32/ISO-HDLC computation over [data, data+len). */",
            f"static uint32_t _crc32_update(uint32_t state, const void *data, size_t len) {{",
            f"    const uint8_t *buf = (const uint8_t *)data;",
            f"    while (len--)",
            f"        state = _crc32_table[(state ^ *buf++) & 0xFF] ^ (state >> 8);",
            f"    return state;",
            f"}}",
            "",
            f"uint32_t {n}_crc32(const void *data, size_t len) {{",
            f"    return _crc32_update(0xFFFFFFFFUL, data, len) ^ 0xFFFFFFFFUL;",
            f"}}",
            "",
            # ------------------------------------------------------------------
            # P0-FIX 1 (cont.): frame_crc chains header then payload correctly.
            # ------------------------------------------------------------------
            # ------------------------------------------------------------------
            # P0-FIX 1: frame_crc encodes header bytes (with crc32=0) to wire
            # byte order BEFORE computing CRC so CRC is 100% host-independent.
            # ------------------------------------------------------------------
            f"uint32_t {n}_frame_crc(const {p.header_struct_name} *hdr,",
            f"                        const void *payload, size_t pay_len) {{",
            f"    {p.header_struct_name} tmp = *hdr;",
            f"    tmp.crc32 = 0U;  /* CRC field must be zeroed before hashing */",
            f"    {n}_hdr_encode(&tmp); /* Convert header fields to wire byte order */",
            f"    uint32_t state = 0xFFFFFFFFUL;",
            f"    state = _crc32_update(state, &tmp, sizeof(tmp));  /* hash wire header */",
            f"    if (pay_len > 0U && payload != NULL)",
            f"        state = _crc32_update(state, payload, pay_len); /* chain wire payload */",
            f"    return state ^ 0xFFFFFFFFUL;",
            f"}}",
            "",
            f"void {n}_hdr_init({p.header_struct_name} *hdr, uint8_t opcode,",
            f"                  uint32_t sess_id, uint32_t seq, uint16_t pay_len) {{",
            f"    memset(hdr, 0, sizeof(*hdr));",
            f"    hdr->magic       = {p.name}_MAGIC;",
            f"    hdr->version     = {p.name}_VERSION;",
            f"    hdr->opcode      = opcode;",
            f"    hdr->payload_len = pay_len;",
            f"    hdr->seq         = seq;",
            f"    hdr->session_id  = sess_id;",
            f"    /* Usage:",
            f"     *   fill payload, call msg_encode(payload),",
            f"     *   hdr->crc32 = {n}_frame_crc(hdr, payload, pay_len);",
            f"     *   {n}_hdr_encode(hdr);  // convert header to {p.endian}-endian wire order",
            f"     *   send(hdr, payload); */",
            f"}}",


            "",
            f"int {n}_hdr_validate(const {p.header_struct_name} *hdr,",
            f"                     const void *payload, size_t pay_len) {{",
            f"    /* Assumes hdr has already been through {n}_hdr_decode(). */",
            f"    if (hdr->magic != {p.name}_MAGIC)                   return -1; /* bad magic */",
            f"    if ((hdr->version >> 16) != {p.name}_VERSION_MAJOR) return -2; /* unsupported major version */",
            f"    if (hdr->payload_len > {p.name}_MAX_PAYLOAD)        return -3; /* payload too large */",
            f"    if (hdr->payload_len != (uint16_t)pay_len)          return -4; /* length mismatch */",
            f"    if ({n}_frame_crc(hdr, payload, pay_len) != hdr->crc32) return -5; /* CRC mismatch */",
            f"    if ({n}_opcode_str(hdr->opcode)[0] == '<')          return -6; /* invalid/unknown opcode */",
            f"    return 0;",
            f"}}",

            "",
            # ------------------------------------------------------------------
            # P0-FIX 2: explicit encode/decode converts between host and wire order.
            # ------------------------------------------------------------------
            f"/* P0-FIX: byte-order conversion — apply to every header before send/after recv */",
            f"void {n}_hdr_encode({p.header_struct_name} *hdr) {{",
            f"    hdr->magic       = {p.name}_TO_WIRE32(hdr->magic);",
            f"    hdr->version     = {p.name}_TO_WIRE32(hdr->version);",
            f"    hdr->payload_len = {p.name}_TO_WIRE16(hdr->payload_len);",
            f"    hdr->seq         = {p.name}_TO_WIRE32(hdr->seq);",
            f"    hdr->session_id  = {p.name}_TO_WIRE32(hdr->session_id);",
            f"    hdr->crc32       = {p.name}_TO_WIRE32(hdr->crc32);",
            f"    /* opcode and flags are single bytes — no swap needed */",
            f"}}",
            "",
            f"void {n}_hdr_decode({p.header_struct_name} *hdr) {{",
            f"    hdr->magic       = {p.name}_FROM_WIRE32(hdr->magic);",
            f"    hdr->version     = {p.name}_FROM_WIRE32(hdr->version);",
            f"    hdr->payload_len = {p.name}_FROM_WIRE16(hdr->payload_len);",
            f"    hdr->seq         = {p.name}_FROM_WIRE32(hdr->seq);",
            f"    hdr->session_id  = {p.name}_FROM_WIRE32(hdr->session_id);",
            f"    hdr->crc32       = {p.name}_FROM_WIRE32(hdr->crc32);",
            f"}}",
            "",
            "/* === Per-message payload wire serialization functions === */",
            self._payload_serialization_code(),
            "",
            self._opcode_map(),
        ]) + "\n"

    def _payload_serialization_code(self) -> str:
        p = self.p
        pname = p.name
        blocks = []
        for msg in p.messages:
            mname = msg.name.lower()
            enc_lines = [f"void {mname}_encode({mname}_t *m) {{", "    (void)m;"]
            dec_lines = [f"void {mname}_decode({mname}_t *m) {{", "    (void)m;"]

            for f in msg.fields:
                if f.array_size is not None:
                    if f.ctype in ("uint16_t", "int16_t"):
                        enc_lines.append(f"    for (size_t i = 0; i < {f.array_size}; i++) m->{f.name}[i] = {pname}_TO_WIRE16(m->{f.name}[i]);")
                        dec_lines.append(f"    for (size_t i = 0; i < {f.array_size}; i++) m->{f.name}[i] = {pname}_FROM_WIRE16(m->{f.name}[i]);")
                    elif f.ctype in ("uint32_t", "int32_t"):
                        enc_lines.append(f"    for (size_t i = 0; i < {f.array_size}; i++) m->{f.name}[i] = {pname}_TO_WIRE32(m->{f.name}[i]);")
                        dec_lines.append(f"    for (size_t i = 0; i < {f.array_size}; i++) m->{f.name}[i] = {pname}_FROM_WIRE32(m->{f.name}[i]);")
                else:
                    if f.ctype in ("uint16_t", "int16_t"):
                        enc_lines.append(f"    m->{f.name} = {pname}_TO_WIRE16(m->{f.name});")
                        dec_lines.append(f"    m->{f.name} = {pname}_FROM_WIRE16(m->{f.name});")
                    elif f.ctype in ("uint32_t", "int32_t"):
                        enc_lines.append(f"    m->{f.name} = {pname}_TO_WIRE32(m->{f.name});")
                        dec_lines.append(f"    m->{f.name} = {pname}_FROM_WIRE32(m->{f.name});")
                    elif f.ctype in ("uint64_t", "int64_t"):
                        enc_lines.append(f"    m->{f.name} = {pname}_TO_WIRE64(m->{f.name});")
                        dec_lines.append(f"    m->{f.name} = {pname}_FROM_WIRE64(m->{f.name});")
                    elif f.ctype == "float":
                        enc_lines.append(f"    {{ uint32_t u = _proto_f32_to_u32(m->{f.name}); u = {pname}_TO_WIRE32(u); m->{f.name} = _proto_u32_to_f32(u); }}")
                        dec_lines.append(f"    {{ uint32_t u = _proto_f32_to_u32(m->{f.name}); u = {pname}_FROM_WIRE32(u); m->{f.name} = _proto_u32_to_f32(u); }}")
                    elif f.ctype == "double":
                        enc_lines.append(f"    {{ uint64_t u = _proto_f64_to_u64(m->{f.name}); u = {pname}_TO_WIRE64(u); m->{f.name} = _proto_u64_to_f64(u); }}")
                        dec_lines.append(f"    {{ uint64_t u = _proto_f64_to_u64(m->{f.name}); u = {pname}_FROM_WIRE64(u); m->{f.name} = _proto_u64_to_f64(u); }}")

            enc_lines.append("}")
            dec_lines.append("}")
            blocks.append("\n".join(enc_lines) + "\n\n" + "\n".join(dec_lines))

        return "\n\n".join(blocks)




# ---------------------------------------------------------------------------
# JSON manifest helper
# ---------------------------------------------------------------------------

def _field_wire_size(f: Field) -> int:
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

def _msg_wire_size(m: Message) -> int:
    return sum(_field_wire_size(f) for f in m.fields)

def protocol_to_dict(proto: Protocol) -> dict:
    return {
        "name":        proto.name,
        "version":     f"{proto.version_major}.{proto.version_minor}.{proto.version_patch}",
        "magic":       f"0x{proto.magic:08X}",
        "pattern":     proto.pattern,
        "endian":      proto.endian,
        "max_payload": proto.max_payload_size,
        "seed":        proto.seed,
        "description": proto.description,
        "enums": [
            {
                "name":    e.name,
                "members": [{"name": m, "value": v} for m, v in e.members],
            }
            for e in proto.enums
        ],
        "messages": [
            {
                "name":        m.name,
                "opcode":      f"0x{m.opcode:02X}",
                "direction":   m.direction,
                "description": m.description,
                "wire_size":   _msg_wire_size(m),
                "fields": [
                    {
                        "name":      f.name,
                        "type":      f.ctype,
                        "wire_size": _field_wire_size(f),
                        **({"bits": f.bits} if f.bits is not None else {}),
                        **({"array_size": f.array_size} if f.array_size is not None else {}),
                        "comment":   f.comment,
                    }
                    for f in m.fields
                ],
            }
            for m in proto.messages
        ],
    }



# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Generate a unique random C protocol VIQ header + stub.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-o", "--output",   default=None, help="Output directory")
    ap.add_argument("-n", "--name",     default=None, help="Protocol name prefix")
    ap.add_argument("-m", "--messages", type=int, default=None, help="Number of messages (1-254)")
    ap.add_argument("-f", "--fields",   type=int, default=None, help="Max fields per struct (1-64)")
    ap.add_argument("-p", "--pattern",  default="auto",
                    choices=["auto"] + PATTERNS, help="Protocol pattern")
    ap.add_argument("--no-impl",        action="store_true", help="Skip .c stub")
    ap.add_argument("--seed",           default=None, help="Hex seed to reproduce a run")
    ap.add_argument("--list-seeds",     action="store_true", help="List past seeds and exit")
    ap.add_argument("--json",           action="store_true", help="Also write JSON manifest")
    ap.add_argument("--spin",           action="store_true",
                    help="Generate Promela model and run SPIN formal verification")
    ap.add_argument("--no-verify",      action="store_true",
                    help="With --spin: generate .pml but skip running SPIN")
    ap.add_argument("-v", "--verbose",  action="store_true", help="Print code to stdout")
    return ap.parse_args()


def main() -> int:
    args = parse_args()

    if args.list_seeds:
        _list_seeds()
        return 0

    # Validate argument bounds
    if args.messages is not None and not (1 <= args.messages <= 254):
        print(f"[gen_protocol]  error: --messages must be between 1 and 254 (got {args.messages})")
        return 1
    if args.fields is not None and not (1 <= args.fields <= 64):
        print(f"[gen_protocol]  error: --fields must be between 1 and 64 (got {args.fields})")
        return 1
    if args.seed is not None and not _re.fullmatch(r"[0-9a-fA-F]{32}", args.seed):
        print(f"[gen_protocol]  error: --seed must be a 32-character hexadecimal string (got {args.seed!r})")
        return 1



    seed = args.seed if args.seed else _make_seed()
    rng  = Random(seed)

    print(f"[gen_protocol]  seed = {seed}")

    gen   = ProtocolGenerator(rng, seed)
    proto = gen.generate(
        name_hint  = args.name,
        n_messages = args.messages,
        max_fields = args.fields,
        pattern    = args.pattern,
    )

    _log_seed(seed, proto.name)

    outdir = Path(args.output) if args.output else Path("out") / proto.name.lower()
    outdir.mkdir(parents=True, exist_ok=True)

    h_name = f"{proto.name.lower()}.h"
    c_name = f"{proto.name.lower()}.c"
    j_name = f"{proto.name.lower()}_manifest.json"

    h_path = outdir / h_name
    c_path = outdir / c_name
    j_path = outdir / j_name

    # Header
    h_code = CHeaderEmitter(proto).emit()
    h_path.write_text(h_code)
    print(f"[gen_protocol]  wrote {h_path}")
    if args.verbose:
        print("\n" + "=" * 78 + "\n" + h_code)

    # Impl stub
    if not args.no_impl:
        c_code = CImplEmitter(proto, h_name).emit()
        c_path.write_text(c_code)
        print(f"[gen_protocol]  wrote {c_path}")
        if args.verbose:
            print("\n" + "=" * 78 + "\n" + c_code)

    # JSON manifest
    if args.json:
        j_path.write_text(json.dumps(protocol_to_dict(proto), indent=2))
        print(f"[gen_protocol]  wrote {j_path}")

    # Promela model + SPIN verification
    spin_ok = True
    if args.spin:
        pml_name = f"{proto.name.lower()}.pml"
        pml_path = outdir / pml_name
        pml_code = PromelaEmitter(proto).emit()
        pml_path.write_text(pml_code)
        print(f"[gen_protocol]  wrote {pml_path}")
        if args.verbose:
            print("\n" + "=" * 78 + "\n" + pml_code)

        if not args.no_verify:
            verifier = SpinVerifier(pml_path, verbose=args.verbose)
            vresult  = verifier.verify()
            spin_ok  = vresult["passed"]

            # Write verification report
            rpt_path = outdir / f"{proto.name.lower()}_spin_report.json"
            rpt_path.write_text(json.dumps(vresult, indent=2))
            print(f"[gen_protocol]  wrote {rpt_path}")

            status = "\033[32m✓ PASS\033[0m" if spin_ok else "\033[31m✗ FAIL\033[0m"
            print(f"\n[spin]  Overall result: {status} — {vresult['summary']}")
        else:
            print("[spin]  Promela model written; --no-verify set, skipping SPIN run.")

    print(
        f"\n[gen_protocol]  Protocol : {proto.name}  "
        f"v{proto.version_major}.{proto.version_minor}.{proto.version_patch}\n"
        f"                Pattern  : {proto.pattern.upper()}\n"
        f"                Magic    : 0x{proto.magic:08X}\n"
        f"                Endian   : {proto.endian}-endian\n"
        f"                Messages : {len(proto.messages)}\n"
        f"                MaxPay   : {proto.max_payload_size} bytes\n"
        + (f"                Verified : {'PASS' if spin_ok else 'FAIL (see report)'}\n"
           if args.spin and not args.no_verify else "")
        + f"\n  To reproduce: python gen_protocol.py --seed {seed}\n"
    )
    return 0 if spin_ok else 1






# ===========================================================================
# SPIN / Promela formal verification model emitter
# ===========================================================================

class PromelaEmitter:
    """
    Emit a SPIN/Promela model for formal verification of the protocol.

    Verification coverage
    ---------------------
    Safety  : opcodes always in valid range; channel never overflows;
              magic constant consistent; no invalid state transitions (fsm).
    Liveness: every C->S request eventually matched by S->C response (reqrsp);
              stream channel never permanently full; pubsub messages only after
              subscribe; rpc calls always returned; fsm never permanently stuck.
    Deadlock: SPIN's built-in deadlock (invalid end-state) detection applies
              automatically.
    """

    CHAN_BUF = 8          # channel buffer depth
    MAX_ITER = 16         # bounded loop unroll for model checking
    SPIN_VERSION = 6      # target SPIN 6.x ltl syntax

    def __init__(self, proto: Protocol) -> None:
        self.p = proto
        self._c2s:  list[Message] = []
        self._s2c:  list[Message] = []
        self._bidi: list[Message] = []
        for m in proto.messages:
            if   m.direction == "C->S": self._c2s.append(m)
            elif m.direction == "S->C": self._s2c.append(m)
            else:                       self._bidi.append(m)

    # -- helpers -----------------------------------------------------------

    def _sym(self, msg: Message) -> str:
        """Promela-safe symbolic name (uppercase, no dashes)."""
        return msg.name.replace("-", "_")

    def _all_syms(self) -> list[str]:
        return [self._sym(m) for m in self.p.messages]

    # -- sections ----------------------------------------------------------

    def _banner(self) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        p  = self.p
        return (
            f"/*\n"
            f" * Promela formal model for {p.name} v{p.version_major}.{p.version_minor}.{p.version_patch}\n"
            f" * Pattern  : {p.pattern.upper()}\n"
            f" * Seed     : {p.seed}\n"
            f" * Generated: {ts}\n"
            f" *\n"
            f" * Verification Scope Notice:\n"
            f" *   This Promela model performs Bounded Model Checking (BMC)\n"
            f" *   (up to MAX_ITER = {self.MAX_ITER}) over abstract message control flow,\n"
            f" *   channel buffer capacity, opcode range invariants, and temporal LTL properties.\n"
            f" *   Low-level C byte-order serialization & CRC integrity are validated\n"
            f" *   separately via C implementation stubs and C runtime frame validation.\n"
            f" *\n"
            f" * Verify with:\n"
            f" *   spin -a {p.name.lower()}.pml\n"
            f" *   gcc -DSAFETY -O2 -o pan pan.c && ./pan -m100000\n"
            f" *   gcc        -O2 -o pan pan.c && ./pan -a -m100000  # liveness\n"
            f" */\n"

        )

    def _defines(self) -> str:
        p = self.p
        lines = [
            f"/* === Protocol constants (all decimal — Promela does not support 0x hex) === */",
            f"#define PROTO_MAGIC         {p.magic}",
            f"#define PROTO_VERSION_MAJOR {p.version_major}",
            f"#define PROTO_VERSION_MINOR {p.version_minor}",
            f"#define PROTO_MAX_PAYLOAD   {p.max_payload_size}",
            f"#define CHAN_BUF            {self.CHAN_BUF}",
            f"#define MAX_ITER           {self.MAX_ITER}",
            f"",
            f"/* === Opcode byte values (decimal) === */",
        ]
        for m in self.p.messages:
            lines.append(f"#define OP_{self._sym(m):<50} {m.opcode}")
        lines += [
            f"",
            f"#define OPCODE_MIN 1",
            f"#define OPCODE_MAX 254",
        ]
        return "\n".join(lines)

    def _mtype(self) -> str:
        syms = self._all_syms()
        body = ",\n    ".join(syms)
        # Plain mtype (SPIN 6 scoped mtype:NAME has caveats; plain mtype is portable)
        return (
            f"/* === Message type enumeration === */\n"
            f"mtype = {{\n    {body}\n}};"
        )

    def _channels(self) -> str:
        lines = [
            "/* === Communication channels === */",
            f"chan c2s  = [{self.CHAN_BUF}] of {{ mtype }};  /* Client -> Server */",
            f"chan s2c  = [{self.CHAN_BUF}] of {{ mtype }};  /* Server -> Client */",
            f"chan bidi = [{self.CHAN_BUF}] of {{ mtype }};  /* Bidirectional    */",
        ]
        return "\n".join(lines)

    def _shared_vars(self) -> str:
        p = self.p
        base = [
            "/* === Shared state variables === */",
            "bool session_active  = false;",
            "bool error_detected  = false;",
            "byte last_opcode     = 0;",
            "byte msg_in_flight   = 0;  /* count of unacknowledged messages */",
        ]
        if p.pattern == "reqrsp":
            base += [
                "bool request_pending = false;",
                "int  requests_sent   = 0;",
                "int  responses_recv  = 0;",
            ]
        elif p.pattern == "pubsub":
            base += [
                "bool subscribed      = false;",
                "int  publishes_sent  = 0;",
                "int  publishes_recv  = 0;",
            ]
        elif p.pattern == "rpc":
            base += [
                "bool call_pending    = false;",
                "int  calls_sent      = 0;",
                "int  returns_recv    = 0;",
            ]
        elif p.pattern == "stream":
            base += [
                "int  frames_sent     = 0;",
                "int  frames_recv     = 0;",
            ]
        elif p.pattern == "fsm":
            # State machine states as bytes
            base += [
                "/* FSM states */",
                "#define FSM_IDLE         0",
                "#define FSM_CONNECTING   1",
                "#define FSM_CONNECTED    2",
                "#define FSM_NEGOTIATING  3",
                "#define FSM_TRANSFERRING 4",
                "#define FSM_DRAINING     5",
                "#define FSM_CLOSING      6",
                "#define FSM_CLOSED       7",
                "#define FSM_ERROR        8",
                "byte fsm_state = FSM_IDLE;",
            ]
        return "\n".join(base)

    # ---- Client proctypes per pattern ------------------------------------

    def _client_reqrsp(self) -> str:
        reqs  = self._c2s  + self._bidi
        resps = self._s2c  + self._bidi
        req_sym  = self._sym(reqs[0])  if reqs  else "NONE"
        resp_sym = self._sym(resps[0]) if resps else "NONE"
        return (
            f"active proctype Client() {{\n"
            f"    mtype resp;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        atomic {{\n"
            f"            assert(!request_pending);  /* no double request */\n"
            f"            c2s ! {req_sym};\n"
            f"            request_pending = true;\n"
            f"            requests_sent++;\n"
            f"            last_opcode = OP_{req_sym};\n"
            f"            assert(last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX);\n"
            f"        }}\n"
            f"        s2c ? resp;\n"
            f"        atomic {{\n"
            f"            request_pending = false;\n"
            f"            responses_recv++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"    /* Signal done via bidi */\n"
            f"    bidi ! {self._sym(self._bidi[0]) if self._bidi else req_sym};\n"
            f"}}"
        )

    def _server_reqrsp(self) -> str:
        reqs  = self._c2s  + self._bidi
        resps = self._s2c  + self._bidi
        req_sym  = self._sym(reqs[0])  if reqs  else "NONE"
        resp_sym = self._sym(resps[0]) if resps else "NONE"
        return (
            f"active proctype Server() {{\n"
            f"    mtype req;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        c2s ? req;\n"
            f"        atomic {{\n"
            f"            assert(req == {req_sym});\n"
            f"            s2c ! {resp_sym};\n"
            f"            last_opcode = OP_{resp_sym};\n"
            f"            assert(last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX);\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _client_stream(self) -> str:
        senders = self._c2s + self._bidi
        sym = self._sym(senders[0]) if senders else self._sym(self.p.messages[0])
        return (
            f"active proctype Client() {{\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER && len(c2s) < CHAN_BUF ->\n"
            f"        atomic {{\n"
            f"            c2s ! {sym};\n"
            f"            frames_sent++;\n"
            f"            last_opcode = OP_{sym};\n"
            f"            assert(last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX);\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _server_stream(self) -> str:
        senders = self._c2s + self._bidi
        sym = self._sym(senders[0]) if senders else self._sym(self.p.messages[0])
        return (
            f"active proctype Server() {{\n"
            f"    mtype frame;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        c2s ? frame;\n"
            f"        atomic {{\n"
            f"            assert(frame == {sym});\n"
            f"            frames_recv++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _client_pubsub(self) -> str:
        sub_msgs = [m for m in self._c2s + self._bidi
                    if "SUBSCRIBE" in m.name or "REGISTER" in m.name]
        pub_msgs = [m for m in self._s2c + self._bidi
                    if "PUBLISH"   in m.name or "PUSH"      in m.name
                    or "NOTIFY"    in m.name or "ANNOUNCE"  in m.name]
        sub_sym = self._sym(sub_msgs[0]) if sub_msgs else self._sym((self._c2s + self._bidi + self.p.messages)[0])
        pub_sym = self._sym(pub_msgs[0]) if pub_msgs else self._sym((self._s2c + self._bidi + self.p.messages)[0])
        return (
            f"active proctype Subscriber() {{\n"
            f"    mtype evt;\n"
            f"    int i = 0;\n"
            f"    /* Subscribe first */\n"
            f"    atomic {{\n"
            f"        c2s ! {sub_sym};\n"
            f"        subscribed = true;\n"
            f"        last_opcode = OP_{sub_sym};\n"
            f"        assert(last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX);\n"
            f"    }}\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        s2c ? evt;\n"
            f"        atomic {{\n"
            f"            assert(subscribed);  /* must be subscribed to receive */\n"
            f"            publishes_recv++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _server_pubsub(self) -> str:
        sub_msgs = [m for m in self._c2s + self._bidi
                    if "SUBSCRIBE" in m.name or "REGISTER" in m.name]
        pub_msgs = [m for m in self._s2c + self._bidi
                    if "PUBLISH"   in m.name or "PUSH"      in m.name
                    or "NOTIFY"    in m.name or "ANNOUNCE"  in m.name]
        sub_sym = self._sym(sub_msgs[0]) if sub_msgs else self._sym((self._c2s + self._bidi + self.p.messages)[0])
        pub_sym = self._sym(pub_msgs[0]) if pub_msgs else self._sym((self._s2c + self._bidi + self.p.messages)[0])
        return (
            f"active proctype Broker() {{\n"
            f"    mtype req;\n"
            f"    int i = 0;\n"
            f"    /* Wait for subscription */\n"
            f"    c2s ? req;\n"
            f"    assert(req == {sub_sym});\n"
            f"    /* Publish events */\n"
            f"    do\n"
            f"    :: i < MAX_ITER && subscribed ->\n"
            f"        atomic {{\n"
            f"            s2c ! {pub_sym};\n"
            f"            publishes_sent++;\n"
            f"            last_opcode = OP_{pub_sym};\n"
            f"            assert(last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX);\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _client_rpc(self) -> str:
        calls   = [m for m in self._c2s + self._bidi if any(
                    v in m.name for v in ["REQUEST","CALL","INVOKE","QUERY","FETCH"])]
        returns = [m for m in self._s2c + self._bidi if any(
                    v in m.name for v in ["RESPONSE","RETURN","RESULT","ACK","REPLY"])]
        call_sym   = self._sym(calls[0])   if calls   else self._sym((self._c2s + self._bidi + self.p.messages)[0])
        return_sym = self._sym(returns[0]) if returns else self._sym((self._s2c + self._bidi + self.p.messages)[0])
        return (
            f"active proctype RPCClient() {{\n"
            f"    mtype ret;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        atomic {{\n"
            f"            assert(!call_pending);\n"
            f"            c2s ! {call_sym};\n"
            f"            call_pending = true;\n"
            f"            calls_sent++;\n"
            f"            last_opcode = OP_{call_sym};\n"
            f"            assert(last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX);\n"
            f"        }}\n"
            f"        s2c ? ret;\n"
            f"        atomic {{\n"
            f"            call_pending = false;\n"
            f"            returns_recv++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _server_rpc(self) -> str:
        calls   = [m for m in self._c2s + self._bidi if any(
                    v in m.name for v in ["REQUEST","CALL","INVOKE","QUERY","FETCH"])]
        returns = [m for m in self._s2c + self._bidi if any(
                    v in m.name for v in ["RESPONSE","RETURN","RESULT","ACK","REPLY"])]
        call_sym   = self._sym(calls[0])   if calls   else self._sym((self._c2s + self._bidi + self.p.messages)[0])
        return_sym = self._sym(returns[0]) if returns else self._sym((self._s2c + self._bidi + self.p.messages)[0])
        return (
            f"active proctype RPCServer() {{\n"
            f"    mtype call;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        c2s ? call;\n"
            f"        atomic {{\n"
            f"            assert(call == {call_sym});\n"
            f"            s2c ! {return_sym};\n"
            f"            last_opcode = OP_{return_sym};\n"
            f"            assert(last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX);\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _client_fsm(self) -> str:
        # Find "connect-like" and "close-like" messages
        connect = next((m for m in self.p.messages if "CONNECT"  in m.name or "HELLO"     in m.name), None)
        ping    = next((m for m in self.p.messages if "PING"     in m.name or "HEARTBEAT" in m.name), None)
        close   = next((m for m in self.p.messages if "CLOSE"    in m.name or "BYE"       in m.name), None)
        acc     = next((m for m in self.p.messages if "ACCEPT"   in m.name or "CONNECTED" in m.name), None)
        rej     = next((m for m in self.p.messages if "REJECT"   in m.name or "ERROR"     in m.name), None)

        conn_sym  = self._sym(connect) if connect else self._sym(self.p.messages[0])
        ping_sym  = self._sym(ping)    if ping    else conn_sym
        close_sym = self._sym(close)   if close   else self._sym(self.p.messages[-1])
        acc_sym   = self._sym(acc)     if acc     else self._sym(self.p.messages[1] if len(self.p.messages) > 1 else self.p.messages[0])
        rej_sym   = self._sym(rej)     if rej     else self._sym(self.p.messages[-1])

        return (
            f"active proctype FSMClient() {{\n"
            f"    mtype resp;\n"
            f"    int i;\n"
            f"    /* IDLE -> CONNECTING */\n"
            f"    assert(fsm_state == FSM_IDLE);\n"
            f"    c2s ! {conn_sym};\n"
            f"    fsm_state = FSM_CONNECTING;\n"
            f"    /* CONNECTING -> CONNECTED or ERROR */\n"
            f"    s2c ? resp;\n"
            f"    if\n"
            f"    :: resp == {acc_sym} ->\n"
            f"        fsm_state = FSM_CONNECTED;\n"
            f"        session_active = true;\n"
            f"    :: resp == {rej_sym} ->\n"
            f"        fsm_state = FSM_ERROR;\n"
            f"        error_detected = true;\n"
            f"        goto done;\n"
            f"    fi;\n"
            f"    /* CONNECTED: exchange data */\n"
            f"    i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER && fsm_state == FSM_CONNECTED ->\n"
            f"        c2s ! {ping_sym};\n"
            f"        last_opcode = OP_{ping_sym};\n"
            f"        assert(last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX);\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"    /* CONNECTED -> CLOSING */\n"
            f"    fsm_state = FSM_CLOSING;\n"
            f"    c2s ! {close_sym};\n"
            f"    fsm_state = FSM_CLOSED;\n"
            f"    session_active = false;\n"
            f"done:\n"
            f"    skip;\n"
            f"}}"
        )

    def _server_fsm(self) -> str:
        connect = next((m for m in self.p.messages if "CONNECT"  in m.name or "HELLO" in m.name), None)
        acc     = next((m for m in self.p.messages if "ACCEPT"   in m.name), None)
        ping    = next((m for m in self.p.messages if "PING"     in m.name or "HEARTBEAT" in m.name), None)
        pong    = next((m for m in self.p.messages if "PONG"     in m.name), None)
        close   = next((m for m in self.p.messages if "CLOSE"    in m.name or "BYE" in m.name), None)

        conn_sym  = self._sym(connect) if connect else self._sym(self.p.messages[0])
        acc_sym   = self._sym(acc)     if acc     else self._sym(self.p.messages[1] if len(self.p.messages) > 1 else self.p.messages[0])
        ping_sym  = self._sym(ping)    if ping    else conn_sym
        pong_sym  = self._sym(pong)    if pong    else acc_sym
        close_sym = self._sym(close)   if close   else self._sym(self.p.messages[-1])

        return (
            f"active proctype FSMServer() {{\n"
            f"    mtype req;\n"
            f"    int i;\n"
            f"    /* Wait for CONNECT */\n"
            f"    c2s ? req;\n"
            f"    assert(req == {conn_sym});\n"
            f"    s2c ! {acc_sym};\n"
            f"    /* Serve data exchange */\n"
            f"    i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        if\n"
            f"        :: nempty(c2s) ->\n"
            f"            c2s ? req;\n"
            f"            if\n"
            f"            :: req == {ping_sym} -> s2c ! {pong_sym};\n"
            f"            :: req == {close_sym} -> break;\n"
            f"            :: else -> skip;\n"
            f"            fi;\n"
            f"        :: i >= MAX_ITER -> break;\n"
            f"        fi;\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _monitor(self) -> str:
        """Monitor proctype — checks cross-cutting invariants via assert."""
        p = self.p
        return (
            f"active proctype Monitor() {{\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        /* Opcode range invariant */\n"
            f"        assert(last_opcode == 0 ||\n"
            f"               (last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX));\n"
            f"        /* Channel buffer invariant */\n"
            f"        assert(len(c2s)  <= CHAN_BUF);\n"
            f"        assert(len(s2c)  <= CHAN_BUF);\n"
            f"        assert(len(bidi) <= CHAN_BUF);\n"
            + (f"        /* reqrsp: responses never exceed requests */\n"
               f"        assert(responses_recv <= requests_sent);\n"
               if p.pattern == "reqrsp" else "")
            + (f"        /* pubsub: no publishes before subscription */\n"
               f"        assert(publishes_recv == 0 || subscribed);\n"
               if p.pattern == "pubsub" else "")
            + (f"        /* rpc: returns never exceed calls */\n"
               f"        assert(returns_recv <= calls_sent);\n"
               if p.pattern == "rpc" else "")
            + (f"        /* fsm: valid state range */\n"
               f"        assert(fsm_state >= FSM_IDLE && fsm_state <= FSM_ERROR);\n"
               if p.pattern == "fsm" else "")
            + f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _ltl_props(self) -> str:
        p = self.p
        common = [
            "/* === LTL temporal properties === */",
            "/* Safety: opcode always in valid range (or zero = uninitialised) */",
            "ltl prop_opcode_valid {",
            "    [] (last_opcode == 0 ||",
            f"        (last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX))",
            "}",
            "",
            "/* Safety: channels never exceed declared depth */",
            "ltl prop_no_chan_overflow {",
            f"    [] (len(c2s) <= CHAN_BUF && len(s2c) <= CHAN_BUF && len(bidi) <= CHAN_BUF)",
            "}",
        ]

        pattern_props: list[str] = []
        if p.pattern == "reqrsp":
            pattern_props = [
                "",
                "/* Liveness: a pending request is always eventually resolved */",
                "ltl prop_request_resolved {",
                "    [] (request_pending -> <> (!request_pending))",
                "}",
                "",
                "/* Safety: server never sends more responses than client sent requests */",
                "ltl prop_response_bound {",
                "    [] (responses_recv <= requests_sent)",
                "}",
            ]
        elif p.pattern == "pubsub":
            pattern_props = [
                "",
                "/* Safety: no published message received before subscribing */",
                "ltl prop_subscribe_before_recv {",
                "    [] (publishes_recv > 0 -> subscribed)",
                "}",
                "",
                "/* Liveness: subscriber eventually receives at least one publish */",
                "ltl prop_eventual_delivery {",
                "    <> (publishes_recv > 0)",
                "}",
            ]
        elif p.pattern == "rpc":
            pattern_props = [
                "",
                "/* Liveness: a pending RPC call always eventually returns */",
                "ltl prop_call_returns {",
                "    [] (call_pending -> <> (!call_pending))",
                "}",
                "",
                "/* Safety: returns never exceed calls */",
                "ltl prop_return_bound {",
                "    [] (returns_recv <= calls_sent)",
                "}",
            ]
        elif p.pattern == "stream":
            pattern_props = [
                "",
                "/* Liveness: stream channel is not permanently full */",
                "ltl prop_stream_progress {",
                f"    [] <> (len(c2s) < CHAN_BUF)",
                "}",
                "",
                "/* Liveness: server eventually receives all frames */",
                "ltl prop_frames_received {",
                "    <> (frames_recv > 0)",
                "}",
            ]
        elif p.pattern == "fsm":
            pattern_props = [
                "",
                "/* Safety: FSM never enters an out-of-range state */",
                "ltl prop_fsm_valid_state {",
                "    [] (fsm_state >= FSM_IDLE && fsm_state <= FSM_ERROR)",
                "}",
                "",
                "/* Safety: once error is detected, it stays detected */",
                "ltl prop_error_sticky {",
                "    [] (error_detected -> [] error_detected)",
                "}",
                "",
                "/* Liveness: if no error, FSM eventually completes (reaches CLOSED) */",
                "ltl prop_fsm_terminates {",
                "    (!error_detected) -> <> (fsm_state == FSM_CLOSED)",
                "}",
            ]

        return "\n".join(common + pattern_props)

    def _proctypes(self) -> str:
        p = self.p
        dispatch = {
            "reqrsp": (self._client_reqrsp, self._server_reqrsp),
            "stream": (self._client_stream, self._server_stream),
            "pubsub": (self._client_pubsub, self._server_pubsub),
            "rpc":    (self._client_rpc,    self._server_rpc),
            "fsm":    (self._client_fsm,    self._server_fsm),
        }
        client_fn, server_fn = dispatch[p.pattern]
        return "\n\n".join([
            "/* === Process definitions === */",
            client_fn(),
            server_fn(),
            self._monitor(),
        ])

    def emit(self) -> str:
        sections = [
            self._banner(),
            self._defines(),
            "",
            self._mtype(),
            "",
            self._channels(),
            "",
            self._shared_vars(),
            "",
            self._proctypes(),
            "",
            self._ltl_props(),
            "",
            "/* end of model */",
        ]
        return "\n".join(sections) + "\n"




# ===========================================================================
# SPIN verifier runner
# ===========================================================================

import subprocess
import shutil
import tempfile

class SpinVerifier:
    """
    Run SPIN formal verification on a Promela model.

    Workflow
    --------
    1. spin -a <model>.pml          → generate pan.c
    2. gcc -DSAFETY -O2 -o pan pan.c → compile safety verifier
    3. ./pan -m500000               → safety check (assertions, deadlock)
    4. gcc         -O2 -o pan pan.c  → recompile without DSAFETY
    5. ./pan -a -m500000            → acceptance-cycle check (liveness)
    """

    MEMLIMIT  = "500000"   # max states
    SPIN_BIN  = shutil.which("spin") or "spin"
    GCC_BIN   = shutil.which("gcc")  or "gcc"

    def __init__(self, pml_path: Path, verbose: bool = False) -> None:
        self.pml     = pml_path
        self.verbose = verbose
        self._work   = pml_path.parent / "_spin_work"

    def _run(self, cmd: list[str], **kw) -> subprocess.CompletedProcess:
        if self.verbose:
            print(f"  $ {' '.join(cmd)}")
        return subprocess.run(cmd, capture_output=True, text=True, **kw)

    def _print_section(self, title: str, text: str) -> None:
        print(f"\n  {'─'*60}")
        print(f"  {title}")
        print(f"  {'─'*60}")
        for line in text.strip().splitlines():
            print(f"    {line}")

    def _parse_pan(self, output: str) -> dict:
        result = {
            "errors":          0,
            "states":          0,
            "transitions":     0,
            "depth":           0,
            "assertion_violated": False,
            "deadlock":        False,
            "acceptance_cycle": False,
            "raw":             output,
        }
        for line in output.splitlines():
            l = line.strip()
            if "errors:" in l:
                try:   result["errors"] = int(l.split("errors:")[1].split(",")[0].split()[0])
                except: pass
            # "   11948 states, stored"  OR  "11948 states,stored"
            if "states," in l and "stored" in l:
                try:   result["states"] = int(l.split()[0].replace(",",""))
                except: pass
            if "transitions" in l:
                try:   result["transitions"] = int(l.split()[0].replace(",",""))
                except: pass
            # "depth reached 495"  or  "max depth limit reached"
            if "depth reached" in l.lower():
                try:   result["depth"] = int(l.split("depth reached")[-1].strip().split()[0].rstrip(","))
                except: pass
            if "assertion violated" in l.lower():
                result["assertion_violated"] = True
            # Only flag deadlock/invalid-end-state on actual error lines (not config lines)
            if ("pan:" in l and "invalid end state" in l.lower()) or \
               ("pan:" in l and "deadlock" in l.lower()):

                result["deadlock"] = True
            if "acceptance cycle" in l.lower():
                result["acceptance_cycle"] = True
        return result

    def verify(self) -> dict:
        self._work.mkdir(parents=True, exist_ok=True)
        results: dict = {
            "pml":      str(self.pml),
            "safety":   {},
            "liveness": {},
            "passed":   False,
            "summary":  "",
        }

        # ── Step 1: generate pan.c ──────────────────────────────────────
        # SPIN always writes pan.c relative to its cwd, so run inside _work.
        import shutil as _sh
        pml_local = self._work / self.pml.name
        _sh.copy(str(self.pml), str(pml_local))   # stage pml into work dir

        print(f"\n[spin]  Generating verifier from {self.pml.name} ...")
        r = self._run(
            [self.SPIN_BIN, "-a", self.pml.name],  # relative; cwd = _work
            cwd=str(self._work),
        )
        if self.verbose and (r.stdout or r.stderr):
            self._print_section("spin -a output", r.stdout + r.stderr)

        pan_c   = self._work / "pan.c"
        pan_bin = self._work / "pan"

        if not pan_c.exists():
            results["summary"] = "FAIL: spin -a did not generate pan.c"
            print(f"[spin]  ERROR: {results['summary']}")
            print(r.stdout); print(r.stderr)
            return results

        # ── Step 2: safety verification ─────────────────────────────────
        print("[spin]  Compiling safety verifier (DSAFETY) ...")
        r = self._run(
            [self.GCC_BIN, "-DSAFETY", "-O2",
             "-o", str(pan_bin.resolve()), str(pan_c.resolve())],
        )
        if r.returncode != 0:
            results["summary"] = "FAIL: gcc compilation error"
            self._print_section("gcc stderr", r.stderr)
            return results

        print(f"[spin]  Running safety check (max states={self.MEMLIMIT}) ...")
        r = self._run([str(pan_bin.resolve()), f"-m{self.MEMLIMIT}"],
                      cwd=str(self._work))
        safety = self._parse_pan(r.stdout + r.stderr)
        results["safety"] = safety
        if self.verbose:
            self._print_section("pan safety output", r.stdout + r.stderr)

        s_ok = (safety["errors"] == 0 and
                not safety["assertion_violated"] and
                not safety["deadlock"])
        print(f"[spin]  Safety  : {'✓ PASS' if s_ok else '✗ FAIL'}"
              f"  (errors={safety['errors']}, states={safety['states']}, "
              f"depth={safety['depth']})")

        # ── Step 3: liveness verification ───────────────────────────────
        print("[spin]  Compiling liveness verifier ...")
        r = self._run(
            [self.GCC_BIN, "-O2",
             "-o", str(pan_bin.resolve()), str(pan_c.resolve())],
        )
        if r.returncode != 0:
            results["summary"] = "FAIL: gcc (liveness) compilation error"
            self._print_section("gcc stderr", r.stderr)
            return results

        print(f"[spin]  Running liveness check (-a, max states={self.MEMLIMIT}) ...")
        r = self._run([str(pan_bin.resolve()), "-a", f"-m{self.MEMLIMIT}"],
                      cwd=str(self._work))
        liveness = self._parse_pan(r.stdout + r.stderr)
        results["liveness"] = liveness
        if self.verbose:
            self._print_section("pan liveness output", r.stdout + r.stderr)

        l_ok = (liveness["errors"] == 0 and
                not liveness["acceptance_cycle"])
        print(f"[spin]  Liveness: {'✓ PASS' if l_ok else '✗ FAIL'}"
              f"  (errors={liveness['errors']}, states={liveness['states']}, "
              f"depth={liveness['depth']})")

        overall = s_ok and l_ok
        results["passed"]  = overall
        results["summary"] = "PASS — no errors found" if overall else "FAIL — see details above"
        return results


    def cleanup(self) -> None:
        import shutil as _sh
        if self._work.exists():
            _sh.rmtree(str(self._work))


if __name__ == "__main__":
    sys.exit(main())
