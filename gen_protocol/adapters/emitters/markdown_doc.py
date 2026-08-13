"""
Adapter emitting Markdown RFC-style documentation (PROTOCOL_SPEC.md).
"""

from datetime import datetime, timezone
from gen_protocol.domain.models import Protocol
from gen_protocol.domain.rules import field_wire_size, msg_wire_size
from gen_protocol.ports.emitter import CodeEmitter


def _md_cell(s) -> str:
    """Escape free text so it cannot break a markdown table cell."""
    return str(s).replace("\\", "\\\\").replace("|", "\\|")


class MarkdownDocEmitter(CodeEmitter):
    def emit(self) -> str:
        p = self.p
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            f"# {p.name} Binary Protocol Specification",
            f"",
            f"**Version:** {p.version_major}.{p.version_minor}.{p.version_patch}  ",
            f"**Pattern:** `{p.pattern.upper()}`  ",
            f"**Magic:** `0x{p.magic:08X}`  ",
            f"**Endianness:** `{p.endian}-endian`  ",
            f"**Max Payload Size:** `{p.max_payload_size}` bytes  ",
            f"**Generated:** `{ts}`  ",
            f"**Seed:** `{p.seed}`",
            f"",
            f"---",
            f"",
            f"## 1. Overview",
            f"",
            f"{p.description}.",
            f"",
            f"## 2. Common Wire Header (22 Bytes)",
            f"",
            f"Every `{p.name}` frame prepends a 22-byte fixed header:",
            f"",
            f"```text",
            f" 0                   1                   2                   3",
            f" 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1",
            f"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+",
            f"|                            magic                              |",
            f"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+",
            f"|            version            |            opcode             |",
            f"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+",
            f"|                          session_id                           |",
            f"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+",
            f"|                           sequence                            |",
            f"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+",
            f"|          payload_len          |             crc32             |",
            f"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+",
            f"|                            crc32 (cont)                       |",
            f"+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+",
            f"```",
            f"",
            f"| Field | Offset | Type | Wire Size | Description |",
            f"|---|---|---|---|---|",
            f"| `magic` | `0..3` | `uint32_t` | 4 B | Must equal `0x{p.magic:08X}` |",
            f"| `version` | `4..5` | `uint16_t` | 2 B | Encoded major.minor version |",
            f"| `opcode` | `6..7` | `uint16_t` | 2 B | Message opcode identifier |",
            f"| `session_id` | `8..11` | `uint32_t` | 4 B | Session identifier |",
            f"| `sequence` | `12..15` | `uint32_t` | 4 B | Monotonic sequence number |",
            f"| `payload_len` | `16..17` | `uint16_t` | 2 B | Byte length of payload |",
            f"| `crc32` | `18..21` | `uint32_t` | 4 B | Frame CRC-32 (ISO-HDLC) |",
            f"",
            f"## 3. Opcode Directory",
            f"",
            f"| Opcode Hex | Opcode Name | Direction | Payload Wire Size | Description |",
            f"|---|---|---|---|---|",
        ]
        for m in p.messages:
            lines.append(f"| `0x{m.opcode:04X}` | `{m.name}` | `{m.direction}` | `{msg_wire_size(m)} B` | {_md_cell(m.description)} |")

        lines += [
            f"",
            f"## 4. Message Payloads",
            f"",
        ]
        for idx, m in enumerate(p.messages):
            lines += [
                f"### 4.{idx + 1} `{m.name}` (Opcode: `0x{m.opcode:04X}`)",
                f"",
                f"**Direction:** `{m.direction}`  ",
                f"**Total Payload Size:** `{msg_wire_size(m)}` bytes  ",
                f"**Description:** {m.description}",
                f"",
                f"| Field Name | Type | Bits / Array | Wire Size | Description |",
                f"|---|---|---|---|---|",
            ]
            for f in m.fields:
                extra = f"{f.bits} bits" if f.bits else (f"[{f.array_size}]" if f.array_size else "—")
                lines.append(f"| `{f.name}` | `{f.ctype}` | `{extra}` | `{field_wire_size(f)} B` | {_md_cell(f.comment)} |")
            lines.append("")

        lines += [
            f"## 5. Encoding & Validation Rules",
            f"",
            f"1. **Byte Order**: Multi-byte integer and floating-point fields MUST be sent in `{p.endian}-endian` order.",
            f"2. **CRC Calculation**: CRC-32 is computed over the 22-byte header with `crc32=0` followed by the wire-encoded payload bytes.",
            f"3. **Validation Error Codes (`{p.name.lower()}_hdr_err_t`)**:",
            f"   - `0` (`{p.name}_HDR_OK`): Frame is valid.",
            f"   - `-1` (`{p.name}_HDR_ERR_MAGIC`): Magic constant mismatch.",
            f"   - `-2` (`{p.name}_HDR_ERR_VERSION`): Version mismatch.",
            f"   - `-3` (`{p.name}_HDR_ERR_PAYLOAD_TOO_BIG`): Payload length exceeds `{p.max_payload_size}` bytes.",
            f"   - `-4` (`{p.name}_HDR_ERR_LEN_MISMATCH`): Payload byte count mismatch.",
            f"   - `-5` (`{p.name}_HDR_ERR_CRC`): CRC-32 checksum error.",
            f"   - `-6` (`{p.name}_HDR_ERR_OPCODE`): Unknown opcode.",
        ]
        return "\n".join(lines) + "\n"
