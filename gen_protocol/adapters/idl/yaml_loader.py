import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from gen_protocol.domain.models import Enum, Field, Message, Protocol
from gen_protocol.domain.rules import (
    calculate_magic, field_wire_size, make_seed, msg_wire_size, sanitize_comment,
    sanitize_proto_name, validate_c_identifier
)
from gen_protocol.domain.types import IDL_TO_C_TYPE, PATTERNS
from gen_protocol.ports.idl import SpecLoader


_VALID_IDL_TYPES = set(IDL_TO_C_TYPE.keys())
_INT_CTYPES = {
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
}
_INT_WIDTH = {
    "uint8_t": 8, "int8_t": 8,
    "uint16_t": 16, "int16_t": 16,
    "uint32_t": 32, "int32_t": 32,
    "uint64_t": 64, "int64_t": 64,
}
# Standard 16-bit opcode range supported by the wire format (0x0000 and 0xFFFF reserved)
_OPCODE_MIN = 0x0001
_OPCODE_MAX = 0xFFFE
# Header payload_len is a uint16 (2 octets) per the wire format.
_MAX_PAYLOAD_BYTES = 0xFFFF


def _parse_opcode(raw) -> int:
    """Parse an opcode literal (int, or decimal/'0x' hex string) and return an int."""
    if isinstance(raw, str):
        s = raw.strip()
        if s.lower().startswith("0x") or s.lower().startswith("-0x"):
            return int(s, 16)
        return int(s, 10)
    return int(raw)



class YamlSpecLoader(SpecLoader):
    def load(self, path: Path, *, seed: Optional[str] = None) -> Protocol:
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

        # Deterministic seed resolution: CLI/argument override -> YAML metadata -> SHA-256(file content)
        if seed:
            resolved_seed = seed.strip().lower()
        elif "seed" in p_info and p_info["seed"]:
            resolved_seed = str(p_info["seed"]).strip().lower()
        else:
            resolved_seed = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()[:32]

        # Magic constant resolution: YAML explicit magic -> calculate_magic(name, seed)
        if "magic" in p_info and p_info["magic"] is not None:
            raw_magic = str(p_info["magic"]).strip()
            if raw_magic.lower().startswith("0x"):
                magic = int(raw_magic, 16)
            else:
                magic = int(raw_magic)
        else:
            magic = calculate_magic(name, resolved_seed)

        endian = str(p_info.get("endian", "big")).lower().strip()
        if endian not in ("little", "big"):
            raise ValueError(f"protocol 'endian' must be 'little' or 'big', got {endian!r}")

        pattern = str(p_info.get("pattern", "rpc")).lower().strip()
        if pattern not in PATTERNS:
            raise ValueError(f"protocol 'pattern' must be one of {PATTERNS}, got {pattern!r}")

        enums = []
        for e in data.get("enums", []):
            ename = validate_c_identifier(e["name"], "enum name")
            members = []
            for m in e.get("members", []):
                m_name = validate_c_identifier(m["name"], "enum member name")
                members.append((m_name, int(m["value"])))
            enums.append(Enum(name=ename, members=members))

        messages = []
        seen_ops: set = set()
        seen_msg_names: set = set()
        for m in data.get("messages", []):
            mname = validate_c_identifier(m.get("name", "<unnamed>"), "message name")
            if mname in seen_msg_names:
                raise ValueError(f"duplicate message name {mname!r}")
            seen_msg_names.add(mname)

            op = _parse_opcode(m.get("opcode", "0x0001"))
            if not (_OPCODE_MIN <= op <= _OPCODE_MAX):
                raise ValueError(
                    f"message {mname!r}: opcode 0x{op:04X} out of range "
                    f"[0x{_OPCODE_MIN:04X}..0x{_OPCODE_MAX:04X}]"
                )
            if op in seen_ops:
                raise ValueError(f"message {mname!r}: duplicate opcode 0x{op:04X}")
            seen_ops.add(op)

            fields = []
            seen_field_names: set = set()
            for f in m.get("fields", []):
                fname = validate_c_identifier(f.get("name"), "field name")
                if fname in seen_field_names:
                    raise ValueError(f"message {mname!r}: duplicate field name {fname!r}")
                seen_field_names.add(fname)

                idl_type = f.get("type", "u32")
                if idl_type not in _VALID_IDL_TYPES:
                    raise ValueError(
                        f"message {mname!r} field {fname!r}: unknown type {idl_type!r}; "
                        f"valid types: {sorted(_VALID_IDL_TYPES)}"
                    )
                ctype = IDL_TO_C_TYPE[idl_type]

                bits = f.get("bits")
                array_size = f.get("array_size")
                if bits is not None and array_size is not None:
                    raise ValueError(
                        f"message {mname!r} field {fname!r}: 'bits' and 'array_size' "
                        f"are mutually exclusive"
                    )

                if bits is not None:
                    if ctype not in _INT_CTYPES:
                        raise ValueError(
                            f"message {mname!r} field {fname!r}: 'bits' is only valid on integer "
                            f"types, not {idl_type!r} ({ctype})"
                        )
                    width = _INT_WIDTH[ctype]
                    if not (1 <= int(bits) <= width):
                        raise ValueError(
                            f"message {mname!r} field {fname!r}: 'bits' must be between 1 and "
                            f"{width} for {idl_type!r}, got {bits}"
                        )

                if array_size is not None and int(array_size) < 1:
                    raise ValueError(
                        f"message {mname!r} field {fname!r}: 'array_size' must be >= 1, got {array_size}"
                    )

                fields.append(Field(
                    name=fname,
                    ctype=ctype,
                    bits=bits,
                    array_size=array_size,
                    comment=sanitize_comment(f.get("comment", ""))
                ))

            wire = sum(field_wire_size(ff) for ff in fields)
            if wire > _MAX_PAYLOAD_BYTES:
                raise ValueError(
                    f"message {mname!r}: payload wire size {wire} bytes exceeds the "
                    f"{_MAX_PAYLOAD_BYTES}-byte limit (header payload_len is uint16)"
                )

            direction = str(m.get("direction", "C->S")).upper().strip()
            if direction not in ("C->S", "S->C", "BIDI"):
                raise ValueError(f"message {mname!r}: invalid direction {direction!r} (must be C->S, S->C, or BIDI)")

            messages.append(Message(
                name=mname,
                opcode=op,
                fields=fields,
                direction=direction,
                description=sanitize_comment(m.get("description", ""))
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
            seed=resolved_seed,
            messages=messages,
            enums=enums,
            header_struct_name=f"{name.lower()}_hdr_t",
            max_payload_size=max_pay,
            endian=endian,
            description=p_info.get("description", "Compiled binary protocol"),
        )
