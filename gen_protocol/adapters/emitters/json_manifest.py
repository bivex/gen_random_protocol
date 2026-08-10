"""
Adapter emitting JSON manifest files.
"""

import json
from gen_protocol.domain.models import Protocol
from gen_protocol.domain.rules import field_wire_size, msg_wire_size
from gen_protocol.domain.types import C_TYPE_TO_IDL
from gen_protocol.ports.emitter import CodeEmitter


def protocol_to_dict(p: Protocol) -> dict:
    """Convert Protocol entity to structured dict."""
    return {
        "name": p.name,
        "version": f"{p.version_major}.{p.version_minor}.{p.version_patch}",
        "pattern": p.pattern,
        "magic": f"0x{p.magic:08X}",
        "endian": p.endian,
        "seed": p.seed,
        "max_payload_size": p.max_payload_size,
        "header_size": 22,
        "messages": [
            {
                "name": m.name,
                "opcode": f"0x{m.opcode:04X}",
                "direction": m.direction,
                "wire_size": msg_wire_size(m),
                "fields": [
                    {
                        "name": f.name,
                        "type": f.ctype,
                        "bits": f.bits,
                        "array_size": f.array_size,
                        "wire_size": field_wire_size(f),
                    }
                    for f in m.fields
                ],
            }
            for m in p.messages
        ],
    }


class JsonManifestEmitter(CodeEmitter):
    def emit(self) -> str:
        return json.dumps(protocol_to_dict(self.p), indent=2) + "\n"
