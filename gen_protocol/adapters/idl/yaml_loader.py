"""
Adapter loading Protocol from YAML or JSON IDL specifications.
"""

import json
from pathlib import Path
from typing import Any, Dict

from gen_protocol.domain.models import Enum, Field, Message, Protocol
from gen_protocol.domain.rules import calculate_magic, make_seed, msg_wire_size, sanitize_proto_name
from gen_protocol.domain.types import IDL_TO_C_TYPE
from gen_protocol.ports.idl import SpecLoader


class YamlSpecLoader(SpecLoader):
    def load(self, path: Path) -> Protocol:
        if not path.exists():
            raise FileNotFoundError(f"Spec file not found: {path}")

        raw_text = path.read_text()
        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml
                data = yaml.safe_load(raw_text)
            except ImportError:
                # Fallback to json if PyYAML missing
                try:
                    data = json.loads(raw_text)
                except Exception:
                    raise ImportError("PyYAML is required to parse .yaml files. Install with 'pip install pyyaml'.")
        else:
            data = json.loads(raw_text)

        p_info = data.get("protocol", {})
        name = sanitize_proto_name(p_info.get("name", "MY_PROTO"))
        ver_parts = str(p_info.get("version", "1.0.0")).split(".")
        v_maj = int(ver_parts[0]) if len(ver_parts) > 0 else 1
        v_min = int(ver_parts[1]) if len(ver_parts) > 1 else 0
        v_pat = int(ver_parts[2]) if len(ver_parts) > 2 else 0

        seed = make_seed()
        magic = calculate_magic(name, seed)
        endian = p_info.get("endian", "big")
        pattern = p_info.get("pattern", "rpc")

        enums = []
        for e in data.get("enums", []):
            members = [(m["name"], int(m["value"])) for m in e.get("members", [])]
            enums.append(Enum(name=e["name"], members=members))

        messages = []
        for m in data.get("messages", []):
            op_raw = m.get("opcode", "0x0001")
            op = int(op_raw, 16) if isinstance(op_raw, str) and op_raw.startswith("0x") else int(op_raw)
            fields = []
            for f in m.get("fields", []):
                idl_type = f.get("type", "u32")
                ctype = IDL_TO_C_TYPE.get(idl_type, idl_type)
                fields.append(Field(
                    name=f["name"],
                    ctype=ctype,
                    bits=f.get("bits"),
                    array_size=f.get("array_size"),
                    comment=f.get("comment", "")
                ))
            messages.append(Message(
                name=m["name"],
                opcode=op,
                fields=fields,
                direction=m.get("direction", "C->S"),
                description=m.get("description", "")
            ))

        max_pay = max((msg_wire_size(m) for m in messages), default=1024)
        max_pay = max(1024, ((max_pay + 3) // 4) * 4)

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
            max_payload_size=max_pay,
            endian=endian,
            description=p_info.get("description", "Compiled binary protocol"),
        )
