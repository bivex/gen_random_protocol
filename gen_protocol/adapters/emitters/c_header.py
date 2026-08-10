"""
Adapter emitting C Header (.h) files.
"""

from datetime import datetime, timezone
from gen_protocol.domain.models import Enum, Field, Message, Protocol
from gen_protocol.ports.emitter import CodeEmitter


class CHeaderEmitter(CodeEmitter):
    def _banner(self) -> str:
        p = self.p
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
            "#ifndef PROTO_FLOAT_HELPERS_",
            "#define PROTO_FLOAT_HELPERS_",
            "static inline uint32_t proto_f32_to_u32_(float f) { uint32_t u; memcpy(&u, &f, sizeof(u)); return u; }",
            "static inline float    proto_u32_to_f32_(uint32_t u) { float f; memcpy(&f, &u, sizeof(f)); return f; }",
            "static inline uint64_t proto_f64_to_u64_(double d) { uint64_t u; memcpy(&u, &d, sizeof(u)); return u; }",
            "static inline double   proto_u64_to_f64_(uint64_t u) { double d; memcpy(&d, &u, sizeof(d)); return d; }",
            "#endif",
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
        lines = []
        for f in msg.fields:
            if f.bits is None:
                continue
            mask = (1 << f.bits) - 1
            mask_hex = f"0x{mask:02X}U" if mask <= 0xFF else f"0x{mask:04X}U"
            pname = self.p.name
            fname = f.name.upper()
            mname = msg.name
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
        p = self.p
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
