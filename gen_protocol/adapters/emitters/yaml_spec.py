"""
Adapter emitting YAML IDL specification files.
"""

from gen_protocol.domain.models import Protocol
from gen_protocol.domain.types import C_TYPE_TO_IDL
from gen_protocol.ports.emitter import CodeEmitter
from gen_protocol.ports.idl import SpecExporter


def protocol_to_yaml_dict(p: Protocol) -> dict:
    """Convert Protocol entity to YAML IDL schema dict."""
    return {
        "protocol": {
            "name": p.name,
            "version": f"{p.version_major}.{p.version_minor}.{p.version_patch}",
            "endian": p.endian,
            "pattern": p.pattern,
            "description": p.description,
        },
        "enums": [
            {
                "name": e.name,
                "members": [{"name": k, "value": v} for k, v in e.members],
            }
            for e in p.enums
        ],
        "messages": [
            {
                "name": m.name,
                "opcode": f"0x{m.opcode:04X}",
                "direction": m.direction,
                "description": m.description,
                "fields": [
                    {
                        "name": f.name,
                        "type": C_TYPE_TO_IDL.get(f.ctype, f.ctype),
                        **({"bits": f.bits} if f.bits else {}),
                        **({"array_size": f.array_size} if f.array_size else {}),
                        "comment": f.comment,
                    }
                    for f in m.fields
                ],
            }
            for m in p.messages
        ],
    }


class YamlSpecEmitter(CodeEmitter, SpecExporter):
    def export(self, proto: Protocol) -> str:
        self.p = proto
        return self.emit()

    def emit(self) -> str:
        d = protocol_to_yaml_dict(self.p)
        try:
            import yaml
            return yaml.dump(d, sort_keys=False)
        except ImportError:
            # Fallback simple YAML formatting if PyYAML is not installed
            lines = [
                "protocol:",
                f"  name: {d['protocol']['name']}",
                f"  version: {d['protocol']['version']}",
                f"  endian: {d['protocol']['endian']}",
                f"  pattern: {d['protocol']['pattern']}",
                f"  description: \"{d['protocol']['description']}\"",
                "",
                "enums:",
            ]
            for e in d["enums"]:
                lines.append(f"  - name: {e['name']}")
                lines.append("    members:")
                for m in e["members"]:
                    lines.append(f"      - {{ name: {m['name']}, value: {m['value']} }}")
            lines.append("")
            lines.append("messages:")
            for m in d["messages"]:
                lines.append(f"  - name: {m['name']}")
                lines.append(f"    opcode: \"{m['opcode']}\"")
                lines.append(f"    direction: {m['direction']}")
                lines.append(f"    description: \"{m['description']}\"")
                lines.append("    fields:")
                for f in m["fields"]:
                    extra = []
                    if "bits" in f: extra.append(f"bits: {f['bits']}")
                    if "array_size" in f: extra.append(f"array_size: {f['array_size']}")
                    extra_str = f", {', '.join(extra)}" if extra else ""
                    lines.append(f"      - {{ name: {f['name']}, type: {f['type']}{extra_str}, comment: \"{f['comment']}\" }}")
            return "\n".join(lines) + "\n"
