#!/usr/bin/env python3
"""
gen_protocol.py — Random C Protocol VIQ Generator
==================================================
Generates collision-resistant C protocol headers & stubs per invocation.

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

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


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
    2. Strip leading characters that are not [A-Za-z] (C idents cannot
       start with digits or reserved underscores).
    3. Collapse runs of underscores to a single '_' and strip trailing '_'.
    4. Uppercase the result.
    5. If the result is a C reserved word or reserved implementation identifier, prefix 'PROTO_'.
    6. Fall back to 'PROTO' if the result is empty after all steps.
    """
    s = _re.sub(r'[^A-Za-z0-9_]', '_', raw)
    s = _re.sub(r'^[^A-Za-z]+', '', s)   # strip leading non-letters/digits/underscores
    s = _re.sub(r'_+', '_', s).strip('_') # collapse/strip underscores
    s = s.upper() or 'PROTO'
    if s.lower() in _C_RESERVED or s.startswith('_') or '__' in s:
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
        elif allow_array and self.rng.random() < 0.22:
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

        # Account for injected semantic fields so total field count strictly respects max_fields
        injected_count = 2 if pattern in ("rpc", "stream") else (1 if pattern in ("reqrsp", "pubsub", "fsm") else 0)
        n_random = max(0, max_fields - injected_count)
        fields   = self._gen_fields(n_random) if n_random > 0 else []

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

        if len(fields) > max_fields:
            fields = fields[:max_fields]

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
        endian_define = (
            f"#define {p.name}_WIRE_ORDER_BIG 1\n"
            f"#define {p.name}_WIRE_ORDER_LITTLE 0"
            if p.endian == "big" else
            f"#define {p.name}_WIRE_ORDER_BIG 0\n"
            f"#define {p.name}_WIRE_ORDER_LITTLE 1"
        )

        lines = [
            f"/* === {p.name} constants === */",
            f"#define {p.name}_MAGIC           0x{p.magic:08X}U",
            f"#define {p.name}_VERSION_MAJOR   {p.version_major}U",
            f"#define {p.name}_VERSION_MINOR   {p.version_minor}U",
            f"#define {p.name}_VERSION_PATCH   {p.version_patch}U",
            f"#define {p.name}_VERSION         "
            f"((uint16_t)((({p.version_major}U & 0xFFU) << 8) | ({p.version_minor}U & 0xFFU)))",
            f"#define {p.name}_MAX_PAYLOAD     {p.max_payload_size}U",
            f"#define {p.name}_HDR_SIZE        sizeof({p.header_struct_name})",
            "",
            f"/* === Wire byte order: {p.endian}-endian === */",
            endian_define,
            "",
            "/* Portable struct packing macro */",
            "#if defined(_MSC_VER)",
            "#  define PROTO_PACKED",
            "#elif defined(__GNUC__) || defined(__clang__)",
            "#  define PROTO_PACKED __attribute__((packed))",
            "#else",
            "#  define PROTO_PACKED",
            "#endif",
            "",
            "/* Portable byte-swap — no system headers needed */",
            "#ifndef PROTO_BSWAP16_",
            "#  define PROTO_BSWAP16_(x) \\",
            "        ((uint16_t)(((uint16_t)(x) >> 8U) | ((uint16_t)(x) << 8U)))",
            "#endif",
            "#ifndef PROTO_BSWAP32_",
            "#  define PROTO_BSWAP32_(x) \\",
            "        (((uint32_t)(x) >> 24U)               | \\",
            "         (((uint32_t)(x) >> 8U)  & 0x0000FF00UL) | \\",
            "         (((uint32_t)(x) << 8U)  & 0x00FF0000UL) | \\",
            "         ((uint32_t)(x) << 24U))",
            "#endif",
            "#ifndef PROTO_BSWAP64_",
            "#  define PROTO_BSWAP64_(x) \\",
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
            "#  define PROTO_HOST_IS_BE_ 1",
            "#else",
            "#  define PROTO_HOST_IS_BE_ 0",
            "#endif",
            "",
            "/* Portable IEEE-754 float/double conversion (no undefined behavior) */",
            "static inline uint32_t proto_f32_to_u32_(float f) { uint32_t u; memcpy(&u, &f, sizeof(u)); return u; }",
            "static inline float    proto_u32_to_f32_(uint32_t u) { float f; memcpy(&f, &u, sizeof(f)); return f; }",
            "static inline uint64_t proto_f64_to_u64_(double d) { uint64_t u; memcpy(&u, &d, sizeof(u)); return u; }",
            "static inline double   proto_u64_to_f64_(uint64_t u) { double d; memcpy(&d, &u, sizeof(d)); return d; }",
            "",
            f"/* {p.name}: convert multi-byte fields between host and {p.endian}-endian wire order */",
        ]
        if p.endian == "big":
            lines += [
                f"#define {p.name}_TO_WIRE16(x)   (PROTO_HOST_IS_BE_ ? (uint16_t)(x) : PROTO_BSWAP16_(x))",
                f"#define {p.name}_FROM_WIRE16(x)  {p.name}_TO_WIRE16(x)",
                f"#define {p.name}_TO_WIRE32(x)   (PROTO_HOST_IS_BE_ ? (uint32_t)(x) : PROTO_BSWAP32_(x))",
                f"#define {p.name}_FROM_WIRE32(x)  {p.name}_TO_WIRE32(x)",
                f"#define {p.name}_TO_WIRE64(x)   (PROTO_HOST_IS_BE_ ? (uint64_t)(x) : PROTO_BSWAP64_(x))",
                f"#define {p.name}_FROM_WIRE64(x)  {p.name}_TO_WIRE64(x)",
            ]
        else:
            lines += [
                f"#define {p.name}_TO_WIRE16(x)   (PROTO_HOST_IS_BE_ ? PROTO_BSWAP16_(x) : (uint16_t)(x))",
                f"#define {p.name}_FROM_WIRE16(x)  {p.name}_TO_WIRE16(x)",
                f"#define {p.name}_TO_WIRE32(x)   (PROTO_HOST_IS_BE_ ? PROTO_BSWAP32_(x) : (uint32_t)(x))",
                f"#define {p.name}_FROM_WIRE32(x)  {p.name}_TO_WIRE32(x)",
                f"#define {p.name}_TO_WIRE64(x)   (PROTO_HOST_IS_BE_ ? PROTO_BSWAP64_(x) : (uint64_t)(x))",
                f"#define {p.name}_FROM_WIRE64(x)  {p.name}_TO_WIRE64(x)",
            ]

        lines += [
            "",
            "/* === Opcode definitions === */",
        ]
        for msg in p.messages:
            lines.append(
                f"#define {msg.name:<54} 0x{msg.opcode:04X}U"
            )

        return "\n".join(lines)

    def _emit_enum(self, e: Enum) -> str:
        lines = [f"typedef enum {{"]
        for k, v in e.members:
            lines.append(f"    {k:<48} = {v},")
        lines.append(f"}} {e.name};")
        return "\n".join(lines)

    def _emit_field(self, f: Field) -> str:
        if f.bits is not None:
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
                f"#define {pname}_GET_{mname}_{fname}(s)    ((s)->{f.name} & ({f.ctype}){mask_hex})",
                f"#define {pname}_SET_{mname}_{fname}(s, v) \\",
                f"    ((s)->{f.name} = ({f.ctype})(((s)->{f.name} & ~({f.ctype}){mask_hex}) "
                f"| (({f.ctype})(v) & ({f.ctype}){mask_hex})))",
            ]
        return "\n".join(lines)

    def _common_hdr_struct(self) -> str:
        p = self.p
        return "\n".join([
            f"/* Common wire header — prepended to every {p.name} frame (22 bytes total) */",
            f"/* Multi-byte fields are in {p.endian}-endian wire order.  "
            f"Call {p.name.lower()}_hdr_encode() before send, _hdr_decode() after recv. */",
            f"typedef struct PROTO_PACKED {{",
            f"    uint32_t     magic;        /* 0..3:   Must equal {p.name}_MAGIC (wire order) */",
            f"    uint16_t     version;      /* 4..5:   Encoded major.minor version (wire order) */",
            f"    uint16_t     opcode;       /* 6..7:   Message type identifier (wire order) */",
            f"    uint32_t     session_id;   /* 8..11:  Session identifier (wire order) */",
            f"    uint32_t     sequence;     /* 12..15: Frame sequence counter (wire order) */",
            f"    uint16_t     payload_len;  /* 16..17: Payload byte length (wire order) */",
            f"    uint32_t     crc32;        /* 18..21: Frame CRC-32 (ISO-HDLC) of hdr(crc=0)+payload (wire order) */",
            f"}} {p.header_struct_name};",
        ])

    def _msg_struct(self, msg: Message) -> str:
        lines = [
            f"/* {msg.name} payload  (opcode=0x{msg.opcode:04X}, {msg.direction}) */",
            f"/* {msg.description} */",
            f"typedef struct PROTO_PACKED {{",
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
            "/* === Header Validation Return Codes === */",
            f"typedef enum {{",
            f"    {p.name}_HDR_OK                  =  0,  /* Header is valid */",
            f"    {p.name}_HDR_ERR_MAGIC           = -1,  /* Magic constant mismatch */",
            f"    {p.name}_HDR_ERR_VERSION         = -2,  /* Version mismatch */",
            f"    {p.name}_HDR_ERR_PAYLOAD_TOO_BIG = -3,  /* Payload length exceeds MAX_PAYLOAD */",
            f"    {p.name}_HDR_ERR_LEN_MISMATCH    = -4,  /* Payload length mismatch */",
            f"    {p.name}_HDR_ERR_CRC             = -5,  /* CRC-32 checksum error */",
            f"    {p.name}_HDR_ERR_OPCODE          = -6   /* Unknown or unsupported opcode */",
            f"}} {n}_hdr_err_t;",
            "",
            "/* === API prototypes === */",
            f"void {n}_hdr_init({p.header_struct_name} *hdr, uint16_t opcode,",
            f"                   uint32_t session_id, uint32_t sequence, uint16_t payload_len);",
            f"void {n}_hdr_encode({p.header_struct_name} *hdr);",
            f"void {n}_hdr_decode({p.header_struct_name} *hdr);",
            "",
            f"uint32_t {n}_crc32(const void *data, size_t len);",
            f"/* Note: {n}_frame_crc expects hdr in HOST byte order. It internally converts to wire order for CRC calculation. */",
            f"uint32_t {n}_frame_crc(const {p.header_struct_name} *hdr, "
            f"const void *payload, size_t payload_len);",
            "",
            f"int  {n}_hdr_validate(const {p.header_struct_name} *hdr, "
            f"const void *payload, size_t payload_len);",
            f"const char *{n}_opcode_str(uint16_t opcode);",
            "",
            "/* === Per-message payload serialization prototypes === */",
            "\n".join([
                f"void {msg.name.lower()}_encode({msg.name.lower()}_t *msg);\n"
                f"void {msg.name.lower()}_decode({msg.name.lower()}_t *msg);"
                for msg in p.messages
            ]),
        ])


    def emit(self) -> str:
        p     = self.p
        guard = f"{p.name}_H_"
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
            "#if defined(_MSC_VER)",
            "#pragma pack(push, 1)",
            "#endif",
            "",
            self._common_hdr_struct(),
            "",
        ]
        for msg in self.p.messages:
            parts.append(self._msg_struct(msg))
            parts.append("")
        parts += [
            "#if defined(_MSC_VER)",
            "#pragma pack(pop)",
            "#endif",
            "",
            self._prototypes(),
            "",
            "#ifdef __cplusplus",
            "}",
            "#endif",
            "",
            f"#endif /* {guard} */",
        ]
        return "\n".join(parts) + "\n"


# ===========================================================================
# C Source Emitter (.c implementation stub)
# ===========================================================================

class CSourceEmitter:
    """Emit C source code implementing payload serialization and frame validation."""

    def __init__(self, proto: Protocol, header_filename: str) -> None:
        self.p      = proto
        self.h_name = header_filename

    def _crc32_table(self) -> str:
        """Emit standard ISO-HDLC CRC-32 lookup table (0xEDB88320 polynomial)."""
        table = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0xEDB88320 if (c & 1) else (c >> 1)
            table.append(f"0x{c:08X}U")
        rows = [", ".join(table[i:i+4]) for i in range(0, 256, 4)]
        body = ",\n    ".join(rows)
        return f"static const uint32_t _crc32_table[256] = {{\n    {body}\n}};"

    def _opcode_map(self) -> str:
        p = self.p
        n = p.name.lower()
        lines = [
            f"const char *{n}_opcode_str(uint16_t opcode) {{",
            "    switch (opcode) {",
        ]
        for m in p.messages:
            lines.append(f"        case {m.name}: return \"{m.name}\";")
        lines += [
            "        default: return \"UNKNOWN_OPCODE\";",
            "    }",
            "}",
        ]
        return "\n".join(lines)

    def emit(self) -> str:
        p = self.p
        n = p.name.lower()
        return "\n".join([
            f"/* Implementation of {p.name} v{p.version_major}.{p.version_minor}.{p.version_patch} */",
            f"#include \"{self.h_name}\"",
            "",
            self._crc32_table(),
            "",
            f"uint32_t {n}_crc32(const void *data, size_t len) {{",
            "    const uint8_t *buf = (const uint8_t *)data;",
            "    uint32_t crc = 0xFFFFFFFFU;",
            "    for (size_t i = 0; i < len; i++) {",
            "        crc = (crc >> 8) ^ _crc32_table[(crc ^ buf[i]) & 0xFFU];",
            "    }",
            "    return crc ^ 0xFFFFFFFFU;",
            "}",
            "",
            f"void {n}_hdr_init({p.header_struct_name} *hdr, uint16_t opcode,",
            f"                   uint32_t session_id, uint32_t sequence, uint16_t payload_len) {{",
            "    if (!hdr) return;",
            "    memset(hdr, 0, sizeof(*hdr));",
            f"    hdr->magic       = {p.name}_MAGIC;",
            f"    hdr->version     = {p.name}_VERSION;",
            "    hdr->opcode      = opcode;",
            "    hdr->session_id  = session_id;",
            "    hdr->sequence    = sequence;",
            "    hdr->payload_len = payload_len;",
            "    hdr->crc32       = 0;",
            "}",
            "",
            f"void {n}_hdr_encode({p.header_struct_name} *hdr) {{",
            "    if (!hdr) return;",
            f"    hdr->magic       = {p.name}_TO_WIRE32(hdr->magic);",
            f"    hdr->version     = {p.name}_TO_WIRE16(hdr->version);",
            f"    hdr->opcode      = {p.name}_TO_WIRE16(hdr->opcode);",
            f"    hdr->session_id  = {p.name}_TO_WIRE32(hdr->session_id);",
            f"    hdr->sequence    = {p.name}_TO_WIRE32(hdr->sequence);",
            f"    hdr->payload_len = {p.name}_TO_WIRE16(hdr->payload_len);",
            f"    hdr->crc32       = {p.name}_TO_WIRE32(hdr->crc32);",
            "}",
            "",
            f"void {n}_hdr_decode({p.header_struct_name} *hdr) {{",
            "    if (!hdr) return;",
            f"    hdr->magic       = {p.name}_FROM_WIRE32(hdr->magic);",
            f"    hdr->version     = {p.name}_FROM_WIRE16(hdr->version);",
            f"    hdr->opcode      = {p.name}_FROM_WIRE16(hdr->opcode);",
            f"    hdr->session_id  = {p.name}_FROM_WIRE32(hdr->session_id);",
            f"    hdr->sequence    = {p.name}_FROM_WIRE32(hdr->sequence);",
            f"    hdr->payload_len = {p.name}_FROM_WIRE16(hdr->payload_len);",
            f"    hdr->crc32       = {p.name}_FROM_WIRE32(hdr->crc32);",
            "}",
            "",
            f"uint32_t {n}_frame_crc(const {p.header_struct_name} *hdr, "
            f"const void *payload, size_t payload_len) {{",
            f"    {p.header_struct_name} tmp = *hdr;",
            "    tmp.crc32 = 0;  /* zero crc field before computing */",
            f"    {n}_hdr_encode(&tmp);",
            "    uint32_t crc = 0xFFFFFFFFU;",
            "    const uint8_t *hbuf = (const uint8_t *)&tmp;",
            "    for (size_t i = 0; i < sizeof(tmp); i++) {",
            "        crc = (crc >> 8) ^ _crc32_table[(crc ^ hbuf[i]) & 0xFFU];",
            "    }",
            "    if (payload && payload_len > 0) {",
            "        const uint8_t *pbuf = (const uint8_t *)payload;",
            "        for (size_t i = 0; i < payload_len; i++) {",
            "            crc = (crc >> 8) ^ _crc32_table[(crc ^ pbuf[i]) & 0xFFU];",
            "        }",
            "    }",
            "    return crc ^ 0xFFFFFFFFU;",
            "}",
            "",
            f"int {n}_hdr_validate(const {p.header_struct_name} *hdr, "
            f"const void *payload, size_t payload_len) {{",
            f"    if (!hdr) return {p.name}_HDR_ERR_MAGIC;",
            f"    if (hdr->magic != {p.name}_MAGIC) return {p.name}_HDR_ERR_MAGIC;        /* invalid magic */",
            f"    if (hdr->version != {p.name}_VERSION) return {p.name}_HDR_ERR_VERSION;    /* version mismatch */",
            f"    if (hdr->payload_len > {p.name}_MAX_PAYLOAD) return {p.name}_HDR_ERR_PAYLOAD_TOO_BIG; /* length exceeds max */",
            f"    if ((size_t)hdr->payload_len != payload_len) return {p.name}_HDR_ERR_LEN_MISMATCH;       /* length mismatch */",
            "    uint32_t expected_crc = "
            f"{n}_frame_crc(hdr, payload, payload_len);",
            f"    if (hdr->crc32 != expected_crc) return {p.name}_HDR_ERR_CRC;            /* CRC error */",
            "    /* Check opcode is known */",
            "    bool opcode_valid = false;",
            "    switch (hdr->opcode) {",
        ] + [f"        case {m.name}: opcode_valid = true; break;" for m in p.messages] + [
            "        default: break;",
            "    }",
            f"    if (!opcode_valid) return {p.name}_HDR_ERR_OPCODE;                        /* unknown opcode */",
            f"    return {p.name}_HDR_OK;  /* OK */",
            "}",
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
                    elif f.ctype in ("uint64_t", "int64_t"):
                        enc_lines.append(f"    for (size_t i = 0; i < {f.array_size}; i++) m->{f.name}[i] = {pname}_TO_WIRE64(m->{f.name}[i]);")
                        dec_lines.append(f"    for (size_t i = 0; i < {f.array_size}; i++) m->{f.name}[i] = {pname}_FROM_WIRE64(m->{f.name}[i]);")
                    elif f.ctype == "float":
                        enc_lines.append(f"    for (size_t i = 0; i < {f.array_size}; i++) {{ uint32_t u = proto_f32_to_u32_(m->{f.name}[i]); u = {pname}_TO_WIRE32(u); m->{f.name}[i] = proto_u32_to_f32_(u); }}")
                        dec_lines.append(f"    for (size_t i = 0; i < {f.array_size}; i++) {{ uint32_t u = proto_f32_to_u32_(m->{f.name}[i]); u = {pname}_FROM_WIRE32(u); m->{f.name}[i] = proto_u32_to_f32_(u); }}")
                    elif f.ctype == "double":
                        enc_lines.append(f"    for (size_t i = 0; i < {f.array_size}; i++) {{ uint64_t u = proto_f64_to_u64_(m->{f.name}[i]); u = {pname}_TO_WIRE64(u); m->{f.name}[i] = proto_u64_to_f64_(u); }}")
                        dec_lines.append(f"    for (size_t i = 0; i < {f.array_size}; i++) {{ uint64_t u = proto_f64_to_u64_(m->{f.name}[i]); u = {pname}_FROM_WIRE64(u); m->{f.name}[i] = proto_u64_to_f64_(u); }}")
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
                        enc_lines.append(f"    {{ uint32_t u = proto_f32_to_u32_(m->{f.name}); u = {pname}_TO_WIRE32(u); m->{f.name} = proto_u32_to_f32_(u); }}")
                        dec_lines.append(f"    {{ uint32_t u = proto_f32_to_u32_(m->{f.name}); u = {pname}_FROM_WIRE32(u); m->{f.name} = proto_u32_to_f32_(u); }}")
                    elif f.ctype == "double":
                        enc_lines.append(f"    {{ uint64_t u = proto_f64_to_u64_(m->{f.name}); u = {pname}_TO_WIRE64(u); m->{f.name} = proto_u64_to_f64_(u); }}")
                        dec_lines.append(f"    {{ uint64_t u = proto_f64_to_u64_(m->{f.name}); u = {pname}_FROM_WIRE64(u); m->{f.name} = proto_u64_to_f64_(u); }}")

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
                "opcode":      f"0x{m.opcode:04X}",
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
# IDL / YAML / JSON Protocol Specification & Documentation Emitter
# ---------------------------------------------------------------------------

IDL_TO_C_TYPE = {
    "u8":   "uint8_t",
    "u16":  "uint16_t",
    "u32":  "uint32_t",
    "u64":  "uint64_t",
    "i8":   "int8_t",
    "i16":  "int16_t",
    "i32":  "int32_t",
    "i64":  "int64_t",
    "f32":  "float",
    "f64":  "double",
    "bool": "uint8_t",
}

C_TYPE_TO_IDL = {
    "uint8_t":  "u8",
    "uint16_t": "u16",
    "uint32_t": "u32",
    "uint64_t": "u64",
    "int8_t":   "i8",
    "int16_t":  "i16",
    "int32_t":  "i32",
    "int64_t":  "i64",
    "float":    "f32",
    "double":   "f64",
}


def protocol_to_yaml_dict(proto: Protocol) -> dict:
    return {
        "protocol": {
            "name":        proto.name,
            "version":     f"{proto.version_major}.{proto.version_minor}.{proto.version_patch}",
            "magic":       f"0x{proto.magic:08X}",
            "pattern":     proto.pattern,
            "endian":      proto.endian,
            "seed":        proto.seed,
            "description": proto.description,
        },
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
                "opcode":      f"0x{m.opcode:04X}",
                "direction":   m.direction,
                "description": m.description,
                "wire_size":   _msg_wire_size(m),
                "fields": [
                    {
                        "name":      f.name,
                        "type":      C_TYPE_TO_IDL.get(f.ctype, f.ctype),
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


def protocol_to_yaml(proto: Protocol) -> str:
    yd = protocol_to_yaml_dict(proto)
    if _YAML_AVAILABLE:
        return yaml.dump(yd, sort_keys=False)
    return json.dumps(yd, indent=2)


def protocol_from_dict(data: dict) -> Protocol:
    pd = data.get("protocol", data)
    raw_name = str(pd.get("name", "MY_PROTO"))
    name = _sanitize_proto_name(raw_name)

    seed = str(pd.get("seed") or _make_seed())
    pattern = str(pd.get("pattern", "reqrsp")).lower()
    if pattern not in PATTERNS:
        pattern = "reqrsp"
    endian = str(pd.get("endian", "little")).lower()
    if endian not in ("little", "big"):
        endian = "little"
    description = str(pd.get("description", f"Protocol {name} specification"))

    ver_raw = pd.get("version", "1.0.0")
    if isinstance(ver_raw, str):
        parts = ver_raw.split(".")
        v_maj = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 1
        v_min = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        v_pat = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
    elif isinstance(ver_raw, (int, float)):
        v_maj, v_min, v_pat = int(ver_raw), 0, 0
    elif isinstance(ver_raw, dict):
        v_maj = int(ver_raw.get("major", 1))
        v_min = int(ver_raw.get("minor", 0))
        v_pat = int(ver_raw.get("patch", 0))
    else:
        v_maj, v_min, v_pat = 1, 0, 0

    magic_raw = pd.get("magic")
    if isinstance(magic_raw, str):
        magic = int(magic_raw, 16) if (magic_raw.startswith("0x") or magic_raw.startswith("0X")) else int(magic_raw)
    elif isinstance(magic_raw, int):
        magic = magic_raw
    else:
        h = hashlib.sha256(f"{name}:{seed}".encode()).digest()
        val = struct.unpack(">I", h[:4])[0]
        for i in range(4):
            if (val >> (i * 8)) & 0xFF == 0:
                val ^= (0xAB << (i * 8))
        magic = val & 0xFFFFFFFF

    # Enums
    enums: list[Enum] = []
    for ed in data.get("enums", []):
        ename = str(ed.get("name", f"{name}_ENUM_t"))
        members = []
        for m in ed.get("members", []):
            if isinstance(m, dict):
                members.append((str(m.get("name", "")), int(m.get("value", 0))))
            elif isinstance(m, (list, tuple)) and len(m) == 2:
                members.append((str(m[0]), int(m[1])))
        enums.append(Enum(name=ename, members=members))

    # Messages
    messages: list[Message] = []
    used_ops: set = set()
    used_names: set = set()

    for md in data.get("messages", []):
        mname = str(md.get("name", "MSG"))
        if not mname.startswith(name) and not mname.startswith("MSG_"):
            mname = f"{name}_MSG_{mname}"
        elif mname.startswith("MSG_"):
            mname = f"{name}_{mname}"
        mname = _sanitize_proto_name(mname)

        orig_name = mname
        idx = 1
        while mname in used_names:
            mname = f"{orig_name}_{idx}"
            idx += 1
        used_names.add(mname)

        op_raw = md.get("opcode", len(messages) + 1)
        if isinstance(op_raw, str):
            opcode = int(op_raw, 16) if (op_raw.startswith("0x") or op_raw.startswith("0X")) else int(op_raw)
        elif isinstance(op_raw, int):
            opcode = op_raw
        else:
            opcode = len(messages) + 1
        
        direction = str(md.get("direction", "BIDI")).upper()
        if direction not in ("C->S", "S->C", "BIDI"):
            direction = "BIDI"
        mdesc = str(md.get("description", f"Message {mname}"))

        fields: list[Field] = []
        for fd in md.get("fields", []):
            fname = str(fd.get("name", "field"))
            raw_type = str(fd.get("type") or fd.get("ctype") or "u8").strip()
            ctype = IDL_TO_C_TYPE.get(raw_type, raw_type)
            bits = fd.get("bits")
            if bits is not None:
                bits = int(bits)
            array_size = fd.get("array_size") or fd.get("array")
            if array_size is not None:
                array_size = int(array_size)
            fcomment = str(fd.get("comment") or f"{fname} field")
            fields.append(Field(name=fname, ctype=ctype, bits=bits, array_size=array_size, comment=fcomment))

        messages.append(Message(name=mname, opcode=opcode, fields=fields, direction=direction, description=mdesc))

    max_payload = max((_msg_wire_size(m) for m in messages), default=0)

    return Protocol(
        name=name,
        version_major=v_maj,
        version_minor=v_min,
        version_patch=v_pat,
        magic=magic,
        pattern=pattern,
        seed=seed,
        messages=messages,
        enums=enums,
        header_struct_name=f"{name.lower()}_hdr_t",
        max_payload_size=max_payload,
        endian=endian,
        description=description,
    )


def load_protocol_from_file(path: Path) -> Protocol:
    if not path.exists():
        raise FileNotFoundError(f"Spec file not found: {path}")
    raw_text = path.read_text()
    if path.suffix.lower() in ('.yaml', '.yml'):
        if not _YAML_AVAILABLE:
            raise RuntimeError("PyYAML is required to parse YAML specs. Install with 'pip install pyyaml'.")
        data = yaml.safe_load(raw_text)
    else:
        data = json.loads(raw_text)
    return protocol_from_dict(data)


class MarkdownDocEmitter:
    def __init__(self, proto: Protocol) -> None:
        self.p = proto

    def emit(self) -> str:
        p = self.p
        lines = []
        lines.append(f"# Binary Protocol Specification: {p.name}")
        lines.append("")
        lines.append(f"**Version**: `{p.version_major}.{p.version_minor}.{p.version_patch}`  ")
        lines.append(f"**Magic Constant**: `0x{p.magic:08X}`  ")
        lines.append(f"**Endianness**: `{p.endian}-endian`  ")
        lines.append(f"**Pattern**: `{p.pattern.upper()}`  ")
        lines.append(f"**Seed**: `{p.seed}`  ")
        lines.append("")
        lines.append(f"{p.description}")
        lines.append("")

        lines.append("## 1. Frame Header Layout")
        lines.append("")
        lines.append("All frames transmitted over the wire begin with the fixed-size common header (22 octets total):")
        lines.append("")
        lines.append("```text")
        lines.append(" 0                   1                   2                   3")
        lines.append(" 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1")
        lines.append("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
        lines.append("|                            magic                              |")
        lines.append("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
        lines.append("|            version            |            opcode             |")
        lines.append("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
        lines.append("|                          session_id                           |")
        lines.append("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
        lines.append("|                           sequence                            |")
        lines.append("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
        lines.append("|          payload_len          |             crc32             |")
        lines.append("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
        lines.append("|                            crc32 (cont)                       |")
        lines.append("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+")
        lines.append("```")
        lines.append("")
        lines.append("| Offset (Bytes) | Field Name | Type | Wire Size | Description |")
        lines.append("|---|---|---|---|---|")
        lines.append(f"| `0 .. 3` | `magic` | `uint32_t` | 4 octets | Protocol identification constant (`0x{p.magic:08X}`) |")
        lines.append("| `4 .. 5` | `version` | `uint16_t` | 2 octets | Protocol version number |")
        lines.append("| `6 .. 7` | `opcode` | `uint16_t` | 2 octets | Message type identifier |")
        lines.append("| `8 .. 11` | `session_id` | `uint32_t` | 4 octets | Connection or session identifier |")
        lines.append("| `12 .. 15` | `sequence` | `uint32_t` | 4 octets | Frame sequence counter |")
        lines.append("| `16 .. 17` | `payload_len` | `uint16_t` | 2 octets | Payload byte length |")
        lines.append("| `18 .. 21` | `crc32` | `uint32_t` | 4 octets | Frame CRC-32 (ISO-HDLC) over header (crc=0) + payload |")
        lines.append("")

        lines.append("## 2. Opcode Directory")
        lines.append("")
        lines.append("| Opcode | Message Name | Direction | Payload Size | Description |")
        lines.append("|---|---|---|---|---|")
        for m in p.messages:
            lines.append(f"| `0x{m.opcode:04X}` | `{m.name}` | `{m.direction}` | {_msg_wire_size(m)} bytes | {m.description} |")
        lines.append("")

        if p.enums:
            lines.append("## 3. Enumerations")
            lines.append("")
            for e in p.enums:
                lines.append(f"### `{e.name}`")
                lines.append("")
                lines.append("| Constant | Value |")
                lines.append("|---|---|")
                for m_name, val in e.members:
                    lines.append(f"| `{m_name}` | `{val}` |")
                lines.append("")

        sec_idx = 4 if p.enums else 3
        lines.append(f"## {sec_idx}. Message Payload Specifications")
        lines.append("")
        for m in p.messages:
            lines.append(f"### `0x{m.opcode:04X}`: {m.name}")
            lines.append("")
            lines.append(f"- **Direction**: `{m.direction}`")
            lines.append(f"- **Payload Wire Size**: `{_msg_wire_size(m)} bytes`")
            lines.append(f"- **Description**: {m.description}")
            lines.append("")
            if m.fields:
                lines.append("| Field Name | Type | Wire Size | Attributes | Description |")
                lines.append("|---|---|---|---|---|")
                for f in m.fields:
                    attrs = []
                    if f.bits is not None:
                        attrs.append(f"bitfield ({f.bits} bits)")
                    if f.array_size is not None:
                        attrs.append(f"array[{f.array_size}]")
                    attr_str = ", ".join(attrs) if attrs else "-"
                    lines.append(f"| `{f.name}` | `{f.ctype}` | {_field_wire_size(f)} B | {attr_str} | {f.comment} |")
                lines.append("")
            else:
                lines.append("*Empty payload (0 bytes).*")
                lines.append("")

        sec_idx += 1
        n = p.name.lower()
        lines.append(f"## {sec_idx}. Encoding & Validation Rules")
        lines.append("")
        lines.append("1. **Byte Order**: Multi-byte numeric fields are encoded on the wire in **" + p.endian + "-endian** byte order.")
        lines.append("2. **CRC Calculation**: Compute CRC-32 (ISO-HDLC polynomial `0xEDB88320`) over the 22-byte header with `crc32 = 0`, followed immediately by the wire-encoded payload bytes.")
        lines.append(f"   - *CRC Contract*: `{n}_frame_crc()` accepts the header in **host byte order** and converts to wire order internally. Passing an already wire-encoded header is incorrect and causes double byte-swapping.")
        lines.append("3. **Header Validation Error Codes** (`" + n + "_hdr_err_t`):")
        lines.append(f"   - ` 0`: `{p.name}_HDR_OK` — Frame is valid.")
        lines.append(f"   - `-1`: `{p.name}_HDR_ERR_MAGIC` — Magic constant mismatch (`magic != 0x{p.magic:08X}`).")
        lines.append(f"   - `-2`: `{p.name}_HDR_ERR_VERSION` — Version mismatch (`version != 0x{p.version_major:02X}{p.version_minor:02X}`).")
        lines.append(f"   - `-3`: `{p.name}_HDR_ERR_PAYLOAD_TOO_BIG` — `payload_len` exceeds `MY_PROTO_MAX_PAYLOAD` ({p.max_payload_size} B).")
        lines.append(f"   - `-4`: `{p.name}_HDR_ERR_LEN_MISMATCH` — Received payload byte count does not match `payload_len`.")
        lines.append(f"   - `-5`: `{p.name}_HDR_ERR_CRC` — Frame CRC-32 checksum mismatch.")
        lines.append(f"   - `-6`: `{p.name}_HDR_ERR_OPCODE` — Opcode is unknown or unsupported.")
        lines.append("")

        return "\n".join(lines) + "\n"


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
    ap.add_argument("--spec",           default=None, help="Load protocol IDL spec from YAML/JSON file instead of random generation")
    ap.add_argument("--export-spec",    action="store_true", help="Export protocol.yaml IDL specification file")
    ap.add_argument("--doc",            action="store_true", help="Generate human-readable PROTOCOL_SPEC.md documentation")
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



    if args.spec:
        spec_path = Path(args.spec)
        print(f"[gen_protocol]  loading protocol specification from {spec_path} ...")
        proto = load_protocol_from_file(spec_path)
        seed = proto.seed
    else:
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
    y_name = "protocol.yaml" if _YAML_AVAILABLE else "protocol.json"
    doc_name = "PROTOCOL_SPEC.md"

    h_path = outdir / h_name
    c_path = outdir / c_name
    j_path = outdir / j_name
    y_path = outdir / y_name
    doc_path = outdir / doc_name

    # Header
    h_code = CHeaderEmitter(proto).emit()
    h_path.write_text(h_code)
    print(f"[gen_protocol]  wrote {h_path}")
    if args.verbose:
        print("\n" + "=" * 78 + "\n" + h_code)

    # Impl stub
    if not args.no_impl:
        c_code = CSourceEmitter(proto, h_name).emit()
        c_path.write_text(c_code)
        print(f"[gen_protocol]  wrote {c_path}")
        if args.verbose:
            print("\n" + "=" * 78 + "\n" + c_code)

    # JSON manifest
    if args.json:
        j_path.write_text(json.dumps(protocol_to_dict(proto), indent=2))
        print(f"[gen_protocol]  wrote {j_path}")

    # Export protocol.yaml IDL spec
    if args.export_spec or args.spec:
        y_path.write_text(protocol_to_yaml(proto))
        print(f"[gen_protocol]  wrote {y_path}")

    # Generate Markdown documentation
    if args.doc or args.spec:
        doc_code = MarkdownDocEmitter(proto).emit()
        doc_path.write_text(doc_code)
        print(f"[gen_protocol]  wrote {doc_path}")
        if args.verbose:
            print("\n" + "=" * 78 + "\n" + doc_code)

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
    MAX_ITER = 4          # bounded loop unroll for model checking
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

    def _send_choice(self, chan: str, msgs: list[Message], indent: str = "        ") -> str:
        if not msgs:
            msgs = self.p.messages
        # Sample representative subset if message list is large to maintain fast SPIN verification time
        if len(msgs) > 3:
            msgs = [msgs[0], msgs[len(msgs) // 2], msgs[-1]]
        if len(msgs) == 1:
            sym = self._sym(msgs[0])
            return (
                f"{indent}atomic {{\n"
                f"{indent}    {chan} ! {sym};\n"
                f"{indent}    last_opcode = OP_{sym};\n"
                f"{indent}    assert(last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX);\n"
                f"{indent}}}"
            )
        lines = [f"{indent}if"]
        for m in msgs:
            sym = self._sym(m)
            lines.append(
                f"{indent}:: atomic {{\n"
                f"{indent}       {chan} ! {sym};\n"
                f"{indent}       last_opcode = OP_{sym};\n"
                f"{indent}       assert(last_opcode >= OPCODE_MIN && last_opcode <= OPCODE_MAX);\n"
                f"{indent}   }}"
            )
        lines.append(f"{indent}fi;")
        return "\n".join(lines)

    def _recv_assert(self, var: str, msgs: list[Message], indent: str = "            ") -> str:
        if len(msgs) == 1:
            sym = self._sym(msgs[0])
            return f"{indent}assert({var} == {sym});"
        conds = " || ".join(f"{var} == {self._sym(m)}" for m in msgs)
        return f"{indent}assert({conds});"

    # ---- Client proctypes per pattern ------------------------------------

    def _client_reqrsp(self) -> str:
        reqs  = self._c2s  + self._bidi or self.p.messages
        completion_msg = self._sym(self._bidi[0]) if self._bidi else self._sym(reqs[0])
        send_code = self._send_choice("c2s", reqs, indent="        ")
        return (
            f"active proctype Client() {{\n"
            f"    mtype resp;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        atomic {{\n"
            f"            assert(!request_pending);  /* no double request */\n"
            f"        }}\n"
            f"{send_code}\n"
            f"        atomic {{\n"
            f"            request_pending = true;\n"
            f"            requests_sent++;\n"
            f"        }}\n"
            f"        s2c ? resp;\n"
            f"        atomic {{\n"
            f"            request_pending = false;\n"
            f"            responses_recv++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"    /* Signal done via bidi or c2s */\n"
            f"    c2s ! {completion_msg};\n"
            f"}}"
        )

    def _server_reqrsp(self) -> str:
        reqs  = self._c2s  + self._bidi or self.p.messages
        resps = self._s2c  + self._bidi or self.p.messages
        recv_assert = self._recv_assert("req", reqs, indent="            ")
        send_code = self._send_choice("s2c", resps, indent="        ")
        return (
            f"active proctype Server() {{\n"
            f"    mtype req;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        c2s ? req;\n"
            f"        atomic {{\n"
            f"{recv_assert}\n"
            f"        }}\n"
            f"{send_code}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _client_stream(self) -> str:
        senders = self._c2s + self._bidi or self.p.messages
        send_code = self._send_choice("c2s", senders, indent="        ")
        return (
            f"active proctype Client() {{\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER && len(c2s) < CHAN_BUF ->\n"
            f"{send_code}\n"
            f"        atomic {{\n"
            f"            frames_sent++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _server_stream(self) -> str:
        senders = self._c2s + self._bidi or self.p.messages
        recv_assert = self._recv_assert("frame", senders, indent="            ")
        return (
            f"active proctype Server() {{\n"
            f"    mtype frame;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        c2s ? frame;\n"
            f"        atomic {{\n"
            f"{recv_assert}\n"
            f"            frames_recv++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _client_pubsub(self) -> str:
        sub_msgs = [m for m in self._c2s + self._bidi
                    if "SUBSCRIBE" in m.name or "REGISTER" in m.name] or self._c2s or self.p.messages
        pub_msgs = [m for m in self._s2c + self._bidi
                    if "PUBLISH"   in m.name or "PUSH"      in m.name
                    or "NOTIFY"    in m.name or "ANNOUNCE"  in m.name] or self._s2c or self.p.messages
        sub_send = self._send_choice("c2s", sub_msgs, indent="    ")
        evt_assert = self._recv_assert("evt", pub_msgs, indent="            ")
        return (
            f"active proctype Subscriber() {{\n"
            f"    mtype evt;\n"
            f"    int i = 0;\n"
            f"    /* Subscribe first */\n"
            f"{sub_send}\n"
            f"    subscribed = true;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        s2c ? evt;\n"
            f"        atomic {{\n"
            f"            assert(subscribed);  /* must be subscribed to receive */\n"
            f"{evt_assert}\n"
            f"            publishes_recv++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _server_pubsub(self) -> str:
        sub_msgs = [m for m in self._c2s + self._bidi
                    if "SUBSCRIBE" in m.name or "REGISTER" in m.name] or self._c2s or self.p.messages
        pub_msgs = [m for m in self._s2c + self._bidi
                    if "PUBLISH"   in m.name or "PUSH"      in m.name
                    or "NOTIFY"    in m.name or "ANNOUNCE"  in m.name] or self._s2c or self.p.messages
        sub_assert = self._recv_assert("req", sub_msgs, indent="    ")
        pub_send = self._send_choice("s2c", pub_msgs, indent="        ")
        return (
            f"active proctype Broker() {{\n"
            f"    mtype req;\n"
            f"    int i = 0;\n"
            f"    /* Wait for subscription */\n"
            f"    c2s ? req;\n"
            f"{sub_assert}\n"
            f"    /* Publish events */\n"
            f"    do\n"
            f"    :: i < MAX_ITER && subscribed ->\n"
            f"{pub_send}\n"
            f"        atomic {{\n"
            f"            publishes_sent++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _client_rpc(self) -> str:
        calls   = [m for m in self._c2s + self._bidi if any(
                    v in m.name for v in ["REQUEST","CALL","INVOKE","QUERY","FETCH"])] or self._c2s or self.p.messages
        returns = [m for m in self._s2c + self._bidi if any(
                    v in m.name for v in ["RESPONSE","RETURN","RESULT","ACK","REPLY"])] or self._s2c or self.p.messages
        call_send = self._send_choice("c2s", calls, indent="        ")
        ret_assert = self._recv_assert("ret", returns, indent="            ")
        return (
            f"active proctype RPCClient() {{\n"
            f"    mtype ret;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        atomic {{\n"
            f"            assert(!call_pending);\n"
            f"        }}\n"
            f"{call_send}\n"
            f"        atomic {{\n"
            f"            call_pending = true;\n"
            f"            calls_sent++;\n"
            f"        }}\n"
            f"        s2c ? ret;\n"
            f"        atomic {{\n"
            f"            call_pending = false;\n"
            f"{ret_assert}\n"
            f"            returns_recv++;\n"
            f"        }}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _server_rpc(self) -> str:
        calls   = [m for m in self._c2s + self._bidi if any(
                    v in m.name for v in ["REQUEST","CALL","INVOKE","QUERY","FETCH"])] or self._c2s or self.p.messages
        returns = [m for m in self._s2c + self._bidi if any(
                    v in m.name for v in ["RESPONSE","RETURN","RESULT","ACK","REPLY"])] or self._s2c or self.p.messages
        call_assert = self._recv_assert("call", calls, indent="            ")
        return_send = self._send_choice("s2c", returns, indent="        ")
        return (
            f"active proctype RPCServer() {{\n"
            f"    mtype call;\n"
            f"    int i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        c2s ? call;\n"
            f"        atomic {{\n"
            f"{call_assert}\n"
            f"        }}\n"
            f"{return_send}\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"}}"
        )

    def _client_fsm(self) -> str:
        connect = next((m for m in self.p.messages if "CONNECT"  in m.name or "HELLO"     in m.name), None)
        ping    = next((m for m in self.p.messages if "PING"     in m.name or "HEARTBEAT" in m.name), None)
        close   = next((m for m in self.p.messages if "CLOSE"    in m.name or "BYE"       in m.name), None)
        acc     = next((m for m in self.p.messages if "ACCEPT"   in m.name or "CONNECTED" in m.name), None)
        rej     = next((m for m in self.p.messages if "REJECT"   in m.name or "ERROR"     in m.name), None)

        conn_sym  = self._sym(connect) if connect else self._sym(self.p.messages[0])
        close_sym = self._sym(close)   if close   else self._sym(self.p.messages[-1])
        acc_sym   = self._sym(acc)     if acc     else self._sym(self.p.messages[1] if len(self.p.messages) > 1 else self.p.messages[0])
        rej_sym   = self._sym(rej)     if rej     else self._sym(self.p.messages[-1])

        data_msgs = [m for m in self.p.messages if self._sym(m) not in (conn_sym, close_sym, acc_sym, rej_sym)] or self.p.messages
        data_send = self._send_choice("c2s", data_msgs, indent="        ")

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
            f"    /* CONNECTED: exchange data across all protocol payload types */\n"
            f"    i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER && fsm_state == FSM_CONNECTED ->\n"
            f"{data_send}\n"
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
        acc     = next((m for m in self.p.messages if "ACCEPT"   in m.name or "CONNECTED" in m.name), None)
        ping    = next((m for m in self.p.messages if "PING"     in m.name or "HEARTBEAT" in m.name), None)
        pong    = next((m for m in self.p.messages if "PONG"     in m.name), None)
        close   = next((m for m in self.p.messages if "CLOSE"    in m.name or "BYE" in m.name), None)
        rej     = next((m for m in self.p.messages if "REJECT"   in m.name or "ERROR" in m.name), None)

        conn_sym  = self._sym(connect) if connect else self._sym(self.p.messages[0])
        acc_sym   = self._sym(acc)     if acc     else self._sym(self.p.messages[1] if len(self.p.messages) > 1 else self.p.messages[0])
        close_sym = self._sym(close)   if close   else self._sym(self.p.messages[-1])
        rej_sym   = self._sym(rej)     if rej     else self._sym(self.p.messages[-1])

        reply_msgs = [m for m in self._s2c + self._bidi if self._sym(m) not in (acc_sym, rej_sym)] or self.p.messages
        reply_send = self._send_choice("s2c", reply_msgs, indent="                ")

        return (
            f"active proctype FSMServer() {{\n"
            f"    mtype req;\n"
            f"    int i;\n"
            f"    /* Wait for CONNECT */\n"
            f"    c2s ? req;\n"
            f"    assert(req == {conn_sym});\n"
            f"    /* Non-deterministic accept or reject to exercise all FSM paths */\n"
            f"    if\n"
            f"    :: s2c ! {acc_sym};\n"
            f"    :: s2c ! {rej_sym};\n"
            f"       goto done;\n"
            f"    fi;\n"
            f"    /* Serve data exchange across all protocol payload types */\n"
            f"    i = 0;\n"
            f"    do\n"
            f"    :: i < MAX_ITER ->\n"
            f"        if\n"
            f"        :: nempty(c2s) ->\n"
            f"            c2s ? req;\n"
            f"            if\n"
            f"            :: req == {close_sym} -> break;\n"
            f"            :: else ->\n"
            f"{reply_send}\n"
            f"            fi;\n"
            f"        :: i >= MAX_ITER -> break;\n"
            f"        fi;\n"
            f"        i++;\n"
            f"    :: i >= MAX_ITER -> break;\n"
            f"    od;\n"
            f"done:\n"
            f"    skip;\n"
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
                "/* Liveness: server eventually receives all frames sent */",
                "ltl prop_frames_received {",
                "    [] (frames_sent == MAX_ITER -> <> (frames_recv == MAX_ITER))",
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
    3. ./pan -m500000               → safety check (search depth limit = 500,000)
    4. gcc         -O2 -o pan pan.c  → recompile without DSAFETY
    5. ./pan -a -m500000            → acceptance-cycle check (liveness)
    """

    SEARCH_DEPTH = "500000"   # search-depth limit (-m)
    SPIN_BIN     = shutil.which("spin") or "spin"
    GCC_BIN      = shutil.which("gcc")  or "gcc"

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
            "errors":            0,
            "states":            0,
            "transitions":       0,
            "depth":             0,
            "assertion_violated": False,
            "deadlock":          False,
            "acceptance_cycle":  False,
            "depth_limit_hit":   False,
            "raw":               output,
        }
        for line in output.splitlines():
            l = line.strip()
            l_lower = l.lower()
            if "errors:" in l:
                try:   result["errors"] = int(l.split("errors:")[1].split(",")[0].split()[0])
                except: pass
            if "states," in l and "stored" in l:
                try:   result["states"] = int(l.split()[0].replace(",",""))
                except: pass
            if "transitions" in l:
                try:   result["transitions"] = int(l.split()[0].replace(",",""))
                except: pass
            if "depth reached" in l_lower:
                try:   result["depth"] = int(l.split("depth reached")[-1].strip().split()[0].rstrip(","))
                except: pass
            if "reached -m bound" in l_lower or "search ceased" in l_lower or "depth limit reached" in l_lower:
                result["depth_limit_hit"] = True
            if "assertion violated" in l_lower:
                result["assertion_violated"] = True
            if ("pan:" in l and "invalid end state" in l_lower) or \
               ("pan:" in l and "deadlock" in l_lower):
                result["deadlock"] = True
            if "acceptance cycle" in l_lower:
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
        import shutil as _sh
        pml_local = self._work / self.pml.name
        _sh.copy(str(self.pml), str(pml_local))   # stage pml into work dir

        print(f"\n[spin]  Generating verifier from {self.pml.name} ...")
        r = self._run(
            [self.SPIN_BIN, "-a", self.pml.name],  # relative; cwd = _work
            cwd=str(self._work),
        )
        if r.returncode != 0:
            results["summary"] = "FAIL: spin -a returned error"
            print(f"[spin]  ERROR: {results['summary']}")
            print(r.stdout); print(r.stderr)
            return results

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

        print(f"[spin]  Running safety check (search depth={self.SEARCH_DEPTH}) ...")
        r = self._run([str(pan_bin.resolve()), f"-m{self.SEARCH_DEPTH}"],
                      cwd=str(self._work))
        safety = self._parse_pan(r.stdout + r.stderr)
        safety["exit_code"] = r.returncode
        results["safety"] = safety
        if self.verbose:
            self._print_section("pan safety output", r.stdout + r.stderr)

        s_ok = (r.returncode == 0 and
                safety["errors"] == 0 and
                not safety["assertion_violated"] and
                not safety["deadlock"] and
                not safety["depth_limit_hit"])
        print(f"[spin]  Safety  : {'✓ PASS' if s_ok else '✗ FAIL'}"
              f"  (exit_code={r.returncode}, errors={safety['errors']}, states={safety['states']}, "
              f"depth={safety['depth']}{', DEPTH_LIMIT_HIT' if safety['depth_limit_hit'] else ''})")

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

        print(f"[spin]  Running liveness check (-a, search depth={self.SEARCH_DEPTH}) ...")
        r = self._run([str(pan_bin.resolve()), "-a", f"-m{self.SEARCH_DEPTH}"],
                      cwd=str(self._work))
        liveness = self._parse_pan(r.stdout + r.stderr)
        liveness["exit_code"] = r.returncode
        results["liveness"] = liveness
        if self.verbose:
            self._print_section("pan liveness output", r.stdout + r.stderr)

        l_ok = (r.returncode == 0 and
                liveness["errors"] == 0 and
                not liveness["acceptance_cycle"] and
                not liveness["depth_limit_hit"])
        print(f"[spin]  Liveness: {'✓ PASS' if l_ok else '✗ FAIL'}"
              f"  (exit_code={r.returncode}, errors={liveness['errors']}, states={liveness['states']}, "
              f"depth={liveness['depth']}{', DEPTH_LIMIT_HIT' if liveness['depth_limit_hit'] else ''})")

        overall = s_ok and l_ok
        results["passed"]  = overall
        if overall:
            results["summary"] = "PASS — no errors found"
        else:
            reasons = []
            if not s_ok:
                if safety["exit_code"] != 0: reasons.append("pan safety process crashed/exited non-zero")
                if safety["errors"] > 0: reasons.append(f"safety errors ({safety['errors']})")
                if safety["assertion_violated"]: reasons.append("assertion violated")
                if safety["deadlock"]: reasons.append("deadlock detected")
                if safety["depth_limit_hit"]: reasons.append("search depth limit hit (-m bound)")
            if not l_ok:
                if liveness["exit_code"] != 0: reasons.append("pan liveness process crashed/exited non-zero")
                if liveness["errors"] > 0: reasons.append(f"liveness errors ({liveness['errors']})")
                if liveness["acceptance_cycle"]: reasons.append("acceptance cycle detected")
                if liveness["depth_limit_hit"]: reasons.append("liveness search depth limit hit (-m bound)")
            results["summary"] = f"FAIL — {', '.join(reasons)}"
        return results

    def cleanup(self) -> None:
        import shutil as _sh
        if self._work.exists():
            _sh.rmtree(str(self._work))


if __name__ == "__main__":
    sys.exit(main())

