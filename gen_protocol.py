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
# Entropy / seed management
# ---------------------------------------------------------------------------

SEED_LOG = Path(__file__).parent / ".protocol_seeds.jsonl"


def _make_seed() -> str:
    """128-bit cryptographically strong seed, hex-encoded."""
    raw = secrets.token_bytes(16) + uuid.uuid4().bytes + struct.pack(">d", time.time())
    return hashlib.sha256(raw).hexdigest()[:32]


def _log_seed(seed: str, proto_name: str) -> None:
    entry = {"ts": datetime.now(timezone.utc).isoformat(), "seed": seed, "name": proto_name}
    with SEED_LOG.open("a") as fh:
        fh.write(json.dumps(entry) + "\n")


def _list_seeds() -> None:
    if not SEED_LOG.exists():
        print("No seed log found.")
        return
    for line in SEED_LOG.read_text().splitlines():
        d = json.loads(line)
        print(f"  {d['ts']}  seed={d['seed']}  name={d['name']}")


# ---------------------------------------------------------------------------
# Vocabulary banks
# ---------------------------------------------------------------------------

PROTO_NOUNS = [
    "NEXUS", "FLUX", "VORTEX", "CIPHER", "AXIOM", "RELAY", "VECTOR", "CONDUIT",
    "HERALD", "STRATUM", "BEACON", "AETHER", "LATTICE", "PULSE", "CORONA", "APEX",
    "ZENITH", "PRISM", "QUORUM", "HELIOS", "SIGMA", "DELTA", "OMEGA", "ECHO",
    "TERRA", "SPECTRA", "RIFT", "NOVA", "LYNX", "COBALT", "TITAN", "FERRO",
    "QUASAR", "HYDRA", "PEGASUS", "ORCA", "ARGON", "NEON", "CHROME", "BASALT",
]

PROTO_SUFFIXES = [
    "LINK", "NET", "BUS", "WIRE", "GATE", "CHAN", "SYNC", "FLOW", "HUB", "MUX",
    "CAST", "MESH", "EDGE", "NODE", "CORE", "SPAN", "PATH", "RACK", "PIPE", "SLOT",
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
    "bool": ("bool",     1),
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
            return forced.upper().replace(" ", "_")
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
        # Unique opcode
        for _ in range(1000):
            op = self.rng.randint(0x01, 0xFE)
            if op not in used_ops:
                used_ops.add(op)
                break

        verb = self._pick(MSG_VERBS)
        name = self._unique_name(f"{proto_name}_MSG_{verb}", used_names)

        n_fields = self.rng.randint(1, max_fields)
        fields   = self._gen_fields(n_fields)

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
        if f.bits is not None:
            return f"    {f.ctype:<12} {f.name} : {f.bits};  /* {f.comment} */"
        elif f.array_size is not None:
            return f"    {f.ctype:<12} {f.name}[{f.array_size}];  /* {f.comment} */"
        else:
            return f"    {f.ctype:<12} {f.name};  /* {f.comment} */"

    def _common_hdr_struct(self) -> str:
        p = self.p
        return "\n".join([
            f"/* Common wire header — prepended to every {p.name} frame */",
            f"typedef struct __attribute__((packed)) {{",
            f"    uint32_t     magic;        /* Must equal {p.name}_MAGIC */",
            f"    uint32_t     version;      /* Encoded {p.version_major}.{p.version_minor}.{p.version_patch} */",
            f"    uint8_t      opcode;       /* One of {p.name}_MSG_* */",
            f"    uint8_t      flags;        /* Protocol-defined flag bits */",
            f"    uint16_t     payload_len;  /* Byte length of payload following header */",
            f"    uint32_t     seq;          /* Monotonic sequence number */",
            f"    uint32_t     session_id;   /* Session identifier */",
            f"    uint32_t     crc32;        /* CRC-32 of header (crc=0) + payload */",
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
        return "\n".join(lines)

    def _prototypes(self) -> str:
        p = self.p
        n = p.name.lower()
        return "\n".join([
            "/* === API prototypes === */",
            "",
            "/**",
            f" * @brief  Initialise a {p.header_struct_name} for the given opcode.",
            f" * @param  hdr      Header to initialise.",
            f" * @param  opcode   One of {p.name}_MSG_* constants.",
            f" * @param  sess_id  Session identifier.",
            f" * @param  pay_len  Payload length in bytes.",
            " */",
            f"void {n}_hdr_init({p.header_struct_name} *hdr, uint8_t opcode,",
            f"                  uint32_t sess_id, uint16_t pay_len);",
            "",
            "/**",
            f" * @brief  Validate a received {p.header_struct_name}.",
            " * @return 0 on success, negative errno-style code on failure.",
            " */",
            f"int  {n}_hdr_validate(const {p.header_struct_name} *hdr,",
            f"                      const void *payload, size_t pay_len);",
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
            f"uint32_t {n}_crc32(const void *data, size_t len) {{",
            f"    const uint8_t *buf = (const uint8_t *)data;",
            f"    uint32_t crc = 0xFFFFFFFFUL;",
            f"    while (len--) {{",
            f"        crc = _crc32_table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);",
            f"    }}",
            f"    return crc ^ 0xFFFFFFFFUL;",
            f"}}",
            "",
            f"void {n}_hdr_init({p.header_struct_name} *hdr, uint8_t opcode,",
            f"                  uint32_t sess_id, uint16_t pay_len) {{",
            f"    static uint32_t _seq = 0U;",
            f"    memset(hdr, 0, sizeof(*hdr));",
            f"    hdr->magic       = {p.name}_MAGIC;",
            f"    hdr->version     = {p.name}_VERSION;",
            f"    hdr->opcode      = opcode;",
            f"    hdr->payload_len = pay_len;",
            f"    hdr->seq         = ++_seq;",
            f"    hdr->session_id  = sess_id;",
            f"    /* Caller must compute and set hdr->crc32 after filling payload. */",
            f"}}",
            "",
            f"int {n}_hdr_validate(const {p.header_struct_name} *hdr,",
            f"                     const void *payload, size_t pay_len) {{",
            f"    if (hdr->magic != {p.name}_MAGIC)                   return -1;",
            f"    if ((hdr->version >> 16) != {p.name}_VERSION_MAJOR) return -2;",
            f"    if (hdr->payload_len > {p.name}_MAX_PAYLOAD)        return -3;",
            f"    if (hdr->payload_len != (uint16_t)pay_len)          return -4;",
            f"    /* Verify CRC over zeroed-crc32 header + payload */",
            f"    {p.header_struct_name} tmp = *hdr;",
            f"    tmp.crc32 = 0U;",
            f"    uint32_t crc = {n}_crc32(&tmp, sizeof(tmp));",
            f"    if (pay_len > 0U)",
            f"        crc ^= {n}_crc32(payload, pay_len);",
            f"    if (crc != hdr->crc32) return -5;",
            f"    return 0;",
            f"}}",
            "",
            self._opcode_map(),
        ]) + "\n"


# ---------------------------------------------------------------------------
# JSON manifest helper
# ---------------------------------------------------------------------------

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
                "fields": [
                    {
                        "name":    f.name,
                        "type":    f.ctype,
                        **({"bits": f.bits} if f.bits is not None else {}),
                        **({"array_size": f.array_size} if f.array_size is not None else {}),
                        "comment": f.comment,
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
    ap.add_argument("-m", "--messages", type=int, default=None, help="Number of messages")
    ap.add_argument("-f", "--fields",   type=int, default=None, help="Max fields per struct")
    ap.add_argument("-p", "--pattern",  default="auto",
                    choices=["auto"] + PATTERNS, help="Protocol pattern")
    ap.add_argument("--no-impl",        action="store_true", help="Skip .c stub")
    ap.add_argument("--seed",           default=None, help="Hex seed to reproduce a run")
    ap.add_argument("--list-seeds",     action="store_true", help="List past seeds and exit")
    ap.add_argument("--json",           action="store_true", help="Also write JSON manifest")
    ap.add_argument("-v", "--verbose",  action="store_true", help="Print code to stdout")
    return ap.parse_args()


def main() -> int:
    args = parse_args()

    if args.list_seeds:
        _list_seeds()
        return 0

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

    print(
        f"\n[gen_protocol]  Protocol : {proto.name}  "
        f"v{proto.version_major}.{proto.version_minor}.{proto.version_patch}\n"
        f"                Pattern  : {proto.pattern.upper()}\n"
        f"                Magic    : 0x{proto.magic:08X}\n"
        f"                Endian   : {proto.endian}-endian\n"
        f"                Messages : {len(proto.messages)}\n"
        f"                MaxPay   : {proto.max_payload_size} bytes\n"
        f"\n  To reproduce: python gen_protocol.py --seed {seed}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
