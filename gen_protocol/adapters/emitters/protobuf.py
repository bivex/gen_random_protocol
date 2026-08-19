"""
Adapter emitting Protocol Buffers (proto3) schema specification files (.proto).
"""

import re
from typing import Dict, List, Set, Tuple

from gen_protocol.domain.models import Enum, Field, Message, Protocol
from gen_protocol.ports.emitter import CodeEmitter

# Protocol Buffers (proto3) reserved keywords that cannot be used directly as field or identifier names
PROTOBUF_RESERVED = frozenset({
    "syntax", "import", "weak", "public", "package", "option", "optional",
    "required", "repeated", "oneof", "map", "reserved", "extensions", "to",
    "max", "message", "enum", "service", "rpc", "returns", "true", "false",
    "group", "double", "float", "int32", "int64", "uint32", "uint64", "sint32",
    "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64", "bool", "string",
    "bytes",
})

# Mapping from C/IDL scalar types to Proto3 types
C_TO_PROTO3_TYPES: Dict[str, str] = {
    "uint8_t":  "uint32",
    "uint16_t": "uint32",
    "uint32_t": "uint32",
    "uint64_t": "uint64",
    "int8_t":   "int32",
    "int16_t":  "int32",
    "int32_t":  "int32",
    "int64_t":  "int64",
    "float":    "float",
    "double":   "double",
    "bool":     "bool",
    "char":     "string",
    # IDL shorthand mappings
    "u8":       "uint32",
    "u16":      "uint32",
    "u32":      "uint32",
    "u64":      "uint64",
    "i8":       "int32",
    "i16":      "int32",
    "i32":      "int32",
    "i64":      "int64",
    "f32":      "float",
    "f64":      "double",
    "string":   "string",
    "bytes":    "bytes",
}


def to_pascal_case(name: str) -> str:
    """Convert snake_case or SCREAMING_SNAKE_CASE identifier to PascalCase."""
    clean = re.sub(r'[^A-Za-z0-9_]', '_', name).strip('_')
    # Strip trailing '_t' suffix common in C type definitions
    if (clean.endswith("_t") or clean.endswith("_T")) and len(clean) > 2:
        clean = clean[:-2]
    parts = [p for p in clean.split('_') if p]
    if not parts:
        return "Msg"
    # Capitalize each part; preserve uppercase acronyms if single letter, else title-case
    result = "".join(part.capitalize() if not part.isupper() or len(part) > 1 else part for part in parts)
    # Ensure it starts with a letter
    if not result[0].isalpha():
        result = "P" + result
    return result


def to_snake_case(name: str) -> str:
    """Convert identifier to snake_case for Protobuf field naming."""
    clean = re.sub(r'[^A-Za-z0-9_]', '_', name).strip('_')
    # Insert underscore between lower and uppercase transitions
    s = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', clean)
    s = re.sub(r'_+', '_', s).lower()
    if not s:
        s = "field"
    if not s[0].isalpha() and s[0] != '_':
        s = "f_" + s
    if s in PROTOBUF_RESERVED:
        s = s + "_val"
    return s


def sanitize_proto_field_name(name: str) -> str:
    """Ensure field name is a valid non-reserved Protobuf snake_case identifier."""
    return to_snake_case(name)


def sanitize_proto_enum_name(name: str) -> str:
    """Convert enum name to clean PascalCase."""
    return to_pascal_case(name)


def sanitize_proto_package_name(name: str) -> str:
    """Produce a clean lowercase package name from protocol name."""
    s = re.sub(r'[^A-Za-z0-9_]', '_', name).strip('_').lower()
    if not s or not s[0].isalpha():
        s = "proto_" + s
    return s


def prefix_enum_member(member: str, prefix: str) -> str:
    """Format enum member with enum prefix, preventing duplicate sub-word repetition."""
    m = re.sub(r'[^A-Za-z0-9_]', '_', member).strip('_').upper()
    p = re.sub(r'[^A-Za-z0-9_]', '_', prefix).strip('_').upper()
    if m.startswith(p):
        return m
    parts = p.split('_')
    for i in range(len(parts)):
        sub = "_".join(parts[i:])
        if m.startswith(sub):
            missing = "_".join(parts[:i])
            return f"{missing}_{m}" if missing else m
    return f"{p}_{m}"


def to_oneof_field_name(msg_name: str, proto_name: str) -> str:
    """Produce clean snake_case oneof payload field name."""
    s = msg_name
    clean_p = re.sub(r'[^A-Za-z0-9_]', '_', proto_name).strip('_')
    if s.upper().startswith(clean_p.upper() + "_"):
        s = s[len(clean_p) + 1:]
    if s.upper().startswith("MSG_"):
        s = s[4:]
    s_snake = to_snake_case(s)
    if s_snake.startswith("msg_"):
        s_snake = s_snake[4:]
    return f"msg_{s_snake}"


class ProtobufEmitter(CodeEmitter):
    """Emitter producing standard Protocol Buffers (proto3) schema definition."""

    def emit(self) -> str:
        p = self.p
        pkg_name = sanitize_proto_package_name(p.name)
        pascal_proto_name = to_pascal_case(p.name)

        lines: List[str] = [
            'syntax = "proto3";',
            '',
            f'package {pkg_name};',
            '',
            f'// Protocol Buffers schema generated for {p.name}',
            f'// Version     : {p.version_major}.{p.version_minor}.{p.version_patch}',
            f'// Pattern     : {p.pattern.upper()}',
            f'// Endianness  : {p.endian}-endian',
            f'// Magic       : 0x{p.magic:08X}',
            f'// Max Payload : {p.max_payload_size} bytes',
            f'// Seed        : {p.seed}',
            f'// Description : {p.description}',
            '',
            f'option go_package = "./{pkg_name}pb";',
            f'option java_package = "com.protocol.{pkg_name}";',
            'option java_multiple_files = true;',
            f'option csharp_namespace = "{pascal_proto_name}";',
            '',
        ]

        # Track enum names mapped to proto enum names
        enum_type_map: Dict[str, str] = {}
        used_enum_member_names: Set[str] = set()

        # 1. Emit Enums
        if p.enums:
            lines.append('// ==========================================')
            lines.append('// Enums')
            lines.append('// ==========================================')
            lines.append('')

            for e in p.enums:
                proto_enum_name = sanitize_proto_enum_name(e.name)
                enum_type_map[e.name] = proto_enum_name
                enum_type_map[e.name.lower()] = proto_enum_name

                # Determine enum prefix for member naming
                clean_e = re.sub(r'[^A-Za-z0-9_]', '_', e.name).strip('_')
                if clean_e.endswith('_t') or clean_e.endswith('_T'):
                    clean_e = clean_e[:-2]
                enum_prefix = clean_e.upper()

                # Check if members have duplicate values
                values = [v for _, v in e.members]
                has_duplicate_values = len(values) != len(set(values))

                # Check if value 0 is present
                has_zero = any(v == 0 for v in values)

                lines.append(f'enum {proto_enum_name} {{')
                if has_duplicate_values:
                    lines.append('  option allow_alias = true;')

                # In proto3, the first enum value must be 0
                members_to_emit: List[Tuple[str, int]] = []
                if not has_zero:
                    unspecified_name = f'{enum_prefix}_UNSPECIFIED'
                    if unspecified_name in used_enum_member_names:
                        unspecified_name = f'{enum_prefix}_{proto_enum_name.upper()}_UNSPECIFIED'
                    used_enum_member_names.add(unspecified_name)
                    members_to_emit.append((unspecified_name, 0))

                for m_name, m_val in e.members:
                    clean_m_name = prefix_enum_member(m_name, enum_prefix)
                    # Ensure global uniqueness across package for proto3
                    orig_name = clean_m_name
                    counter = 1
                    while clean_m_name in used_enum_member_names:
                        clean_m_name = f"{orig_name}_{counter}"
                        counter += 1
                    used_enum_member_names.add(clean_m_name)
                    members_to_emit.append((clean_m_name, m_val))

                # Ensure the member with value 0 is first
                zero_idx = next((i for i, (_, v) in enumerate(members_to_emit) if v == 0), 0)
                if zero_idx != 0:
                    zero_elem = members_to_emit.pop(zero_idx)
                    members_to_emit.insert(0, zero_elem)

                for name_str, val_int in members_to_emit:
                    lines.append(f'  {name_str} = {val_int};')
                lines.append('}')
                lines.append('')

        # 2. Emit Opcode Directory Enum
        lines.append('// ==========================================')
        lines.append('// Opcode Directory')
        lines.append('// ==========================================')
        lines.append('')
        lines.append('enum Opcode {')

        # Check for duplicate opcodes
        op_vals = [m.opcode for m in p.messages]
        if len(op_vals) != len(set(op_vals)):
            lines.append('  option allow_alias = true;')

        lines.append('  OPCODE_UNSPECIFIED = 0;')
        for m in p.messages:
            clean_op_name = re.sub(r'[^A-Za-z0-9_]', '_', m.name).upper()
            if not clean_op_name.startswith("OPCODE_"):
                clean_op_name = f"OPCODE_{clean_op_name}"
            lines.append(f'  {clean_op_name} = {m.opcode};')
        lines.append('}')
        lines.append('')

        # 3. Emit Common Wire Header Message
        lines.append('// ==========================================')
        lines.append('// Common Wire Header (22 Bytes)')
        lines.append('// ==========================================')
        lines.append('')
        lines.append('message Header {')
        lines.append(f'  uint32 magic = 1;         // Protocol identification magic (0x{p.magic:08X})')
        lines.append(f'  uint32 version = 2;       // Encoded version ({p.version_major}.{p.version_minor}.{p.version_patch})')
        lines.append('  uint32 opcode = 3;        // Wire message opcode')
        lines.append('  uint32 session_id = 4;    // Session or channel ID')
        lines.append('  uint32 sequence = 5;      // Monotonic sequence number')
        lines.append('  uint32 payload_len = 6;   // Payload length in bytes')
        lines.append('  uint32 crc32 = 7;         // Frame CRC-32 (ISO-HDLC)')
        if p.auth:
            lines.append(f'  bytes auth_tag = 8;       // Authentication MAC ({p.auth})')
        lines.append('}')
        lines.append('')

        # 4. Emit Individual Message Payloads
        lines.append('// ==========================================')
        lines.append('// Message Payloads')
        lines.append('// ==========================================')
        lines.append('')

        message_pascal_names: Dict[str, str] = {}
        used_msg_names: Set[str] = {"Header", "Frame", "Opcode"}

        for m in p.messages:
            base_msg_name = to_pascal_case(m.name)
            msg_name = base_msg_name
            counter = 1
            while msg_name in used_msg_names:
                msg_name = f"{base_msg_name}{counter}"
                counter += 1
            used_msg_names.add(msg_name)
            message_pascal_names[m.name] = msg_name

            desc_comment = f" // {m.description}" if m.description else ""
            lines.append(f'// Opcode: 0x{m.opcode:04X} | Direction: {m.direction}{desc_comment}')
            lines.append(f'message {msg_name} {{')

            used_field_names: Set[str] = set()
            for idx, f in enumerate(m.fields, start=1):
                field_name = sanitize_proto_field_name(f.name)
                # Ensure unique field name within message
                orig_f_name = field_name
                f_counter = 1
                while field_name in used_field_names:
                    field_name = f"{orig_f_name}_{f_counter}"
                    f_counter += 1
                used_field_names.add(field_name)

                # Determine proto field type
                if f.ctype in enum_type_map:
                    proto_type = enum_type_map[f.ctype]
                else:
                    proto_type = C_TO_PROTO3_TYPES.get(f.ctype, "bytes")

                field_comment_parts = []
                if f.comment:
                    field_comment_parts.append(f.comment)

                # Handle byte arrays / buffers vs repeated scalar arrays
                if f.array_size is not None:
                    if f.ctype in ("uint8_t", "int8_t", "u8", "i8"):
                        # Idiomatic Protobuf representation for byte buffers
                        proto_type = "bytes"
                        field_comment_parts.append(f"Fixed array size: {f.array_size} bytes")
                        type_decl = f"{proto_type} {field_name}"
                    else:
                        field_comment_parts.append(f"Fixed array size: {f.array_size} elements")
                        type_decl = f"repeated {proto_type} {field_name}"
                elif f.bits is not None:
                    field_comment_parts.append(f"Bitfield width: {f.bits} bits")
                    type_decl = f"{proto_type} {field_name}"
                else:
                    type_decl = f"{proto_type} {field_name}"

                comment_str = f" // {', '.join(field_comment_parts)}" if field_comment_parts else ""
                lines.append(f'  {type_decl} = {idx};{comment_str}')

            lines.append('}')
            lines.append('')

        # 5. Emit Unified Frame Envelope Message
        lines.append('// ==========================================')
        lines.append('// Frame Envelope (Top-Level Packet)')
        lines.append('// ==========================================')
        lines.append('')
        lines.append('message Frame {')
        lines.append('  Header header = 1;')
        lines.append('  oneof payload {')

        used_oneof_fields: Set[str] = set()
        tag_idx = 2
        for m in p.messages:
            msg_type = message_pascal_names[m.name]
            field_name = to_oneof_field_name(m.name, p.name)
            field_name = sanitize_proto_field_name(field_name)

            orig_fname = field_name
            cnt = 1
            while field_name in used_oneof_fields:
                field_name = f"{orig_fname}_{cnt}"
                cnt += 1
            used_oneof_fields.add(field_name)

            lines.append(f'    {msg_type} {field_name} = {tag_idx};')
            tag_idx += 1

        lines.append(f'    bytes raw_payload = {tag_idx};')
        lines.append('  }')
        lines.append('}')
        lines.append('')

        # 6. Emit gRPC Service Definition
        lines.append('// ==========================================')
        lines.append('// gRPC Service Interface')
        lines.append('// ==========================================')
        lines.append('')
        service_name = f"{pascal_proto_name}Service"
        lines.append(f'service {service_name} {{')
        lines.append('  // Full-duplex or unified frame exchange')
        lines.append('  rpc Exchange (Frame) returns (Frame);')

        if p.pattern == "stream":
            lines.append('  // Bi-directional streaming channel')
            lines.append('  rpc StreamFrames (stream Frame) returns (stream Frame);')
        elif p.pattern == "pubsub":
            lines.append('  // Topic publish invocation')
            lines.append('  rpc Publish (Frame) returns (Frame);')
            lines.append('  // Topic subscription event stream')
            lines.append('  rpc Subscribe (Frame) returns (stream Frame);')
        elif p.pattern in ("rpc", "reqrsp"):
            # Emit typed RPC methods for C->S messages
            req_msgs = [m for m in p.messages if m.direction in ("C->S", "BIDI")]
            rsp_msgs = [m for m in p.messages if m.direction in ("S->C", "BIDI")]
            for req in req_msgs:
                req_type = message_pascal_names[req.name]
                # Look for matching response message if available
                matched_rsp = next(
                    (
                        rsp for rsp in rsp_msgs
                        if any(
                            keyword in req.name and keyword in rsp.name
                            for keyword in ("CONNECT", "SYNC", "AUTH", "QUERY", "FETCH", "REQUEST", "SUBSCRIBE")
                        )
                    ),
                    None
                )
                rsp_type = message_pascal_names[matched_rsp.name] if matched_rsp else "Frame"
                method_name = to_pascal_case(req.name)
                # Strip prefix for method name
                clean_method = method_name
                for pfx in (pascal_proto_name, "Msg"):
                    if clean_method.startswith(pfx) and len(clean_method) > len(pfx):
                        clean_method = clean_method[len(pfx):]
                clean_method = clean_method or method_name
                # Avoid method name colliding with message type name in protobuf scope
                if clean_method in used_msg_names or clean_method == req_type or clean_method == rsp_type:
                    clean_method = f"Send{clean_method}"
                lines.append(f'  rpc {clean_method} ({req_type}) returns ({rsp_type});')

        lines.append('}')
        lines.append('')

        return "\n".join(lines)


# Backward compatibility alias
ProtoEmitter = ProtobufEmitter
