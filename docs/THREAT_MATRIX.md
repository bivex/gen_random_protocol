# Protocol Security & Threat Matrix Assessment

This document provides a comprehensive security threat matrix, attack surface evaluation, buffer overflow safety analysis, and reverse-engineering complexity assessment for binary protocols produced by `gen_protocol.py`.

---

## 🎯 1. Security & Threat Vector Matrix

| Threat / Attack Vector | Severity | Risk Level | Mitigation & Implementation Countermeasures |
|---|---|---|---|
| **Frame Tampering / Bit-Rot** | High | Low | **ISO-HDLC CRC-32 Checksum (`crc32`)**: Computed over the 22-byte header (with `crc=0`) and wire payload. Checked via `hdr_validate()`. Mismatch returns `MY_PROTO_HDR_ERR_CRC`. |
| **Payload Buffer Overflow** | Critical | Low | **Strict Payload Bounds Enforcement**: Header field `payload_len` is validated against `MY_PROTO_MAX_PAYLOAD`. Length mismatch returns `MY_PROTO_HDR_ERR_PAYLOAD_TOO_BIG`. |
| **Magic Constant Spoofing** | Medium | Low | **SHA-256 Seeded Magic (`magic`)**: 32-bit cryptographically derived constant with zero-byte patching (`0x...`). Invalid magic returns `MY_PROTO_HDR_ERR_MAGIC`. |
| **Opcode Injection Attack** | High | Low | **Strict Enum Range Check**: Opcode directory enforces explicit switch-case matching inside `hdr_validate()`. Unknown opcodes return `MY_PROTO_HDR_ERR_OPCODE`. |
| **Replay Attacks** | High | Medium | **Monotonic Sequence Counter (`sequence`)**: 32-bit sequence counter tracking frame index per session. *Recommendation:* Receiver should enforce sequence window tracking. |
| **Passive Traffic Sniffing** | Medium | High | **No Default Encryption**: Payload fields are transmitted in plaintext wire format. *Recommendation:* Wrap transport in TLS/DTLS or Noise Protocol framework. |
| **Reverse-Engineering & Signature Analysis** | Medium | Low | **Polymorphic Field Layout**: High resistance due to random field order, dynamic endianness, bitfield masking, and unique seed-based magic constants. |

---

## 🔬 2. Reverse-Engineering Complexity Analysis

| Reverse-Engineering Dimension | Obfuscation & Complexity Analysis |
|---|---|
| **Signature Detection** | **High Resistance**: Magic constants use SHA-256 over `name:seed` with zero-byte patching. Static signature analyzers (`binwalk`, `signsearch`) fail to identify known magic headers. |
| **Field Boundary Recovery** | **High Resistance**: Payloads are packed C structs (`PROTO_PACKED`). Fields lack inline type tags or metadata, forcing reversers to manually trace assembly instructions in Ghidra / IDA Pro. |
| **Opcode Mapping** | **High Resistance**: Opcodes are randomly selected from 254 hex values. Traffic analyzers (Wireshark) see raw numbers without protocol dissectors. |
| **Bitfield Dissection** | **High Resistance**: Bitfields ($1..4$ bits) are packed into integer storage cells and accessed via `GET_*` / `SET_*` bitmasks, producing complex control flow graphs in decompilers. |
| **CRC Signature Protection** | **High Resistance**: CRC-32 computation zero-fills the header CRC field, converts to temporary wire byte order, and computes checksum over dual-state buffers. |
| **MultiChain Tunnel Obfuscation** | **Extreme Resistance**: `--multichain` wraps payloads inside $N$ nested bridge frames (`*_MSG_BRIDGE_TO_*`), each with distinct magic constants and opcodes. |

---

## 🛡️ 3. Memory Safety & C Standard Invariants

1. **Undefined Behavior (UB) Avoidance**:
   - `float` and `double` conversions use `memcpy` bit re-interpretation via `proto_f32_to_u32_` and `proto_u64_to_f64_` to prevent pointer aliasing UB.
2. **Struct Alignment Safety**:
   - All wire structs use portable `#pragma pack(push, 1)` or `__attribute__((packed))` macros (`PROTO_PACKED`), eliminating compiler-dependent padding bytes.
3. **Header Validation API (`hdr_validate`)**:
   - Safe validation function returning explicit error enum codes (`MY_PROTO_HDR_OK`, `MY_PROTO_HDR_ERR_MAGIC`, `MY_PROTO_HDR_ERR_VERSION`, `MY_PROTO_HDR_ERR_PAYLOAD_TOO_BIG`, `MY_PROTO_HDR_ERR_LEN_MISMATCH`, `MY_PROTO_HDR_ERR_CRC`, `MY_PROTO_HDR_ERR_OPCODE`).

---

## 🔒 4. Production Security Recommendations

For high-security deployment environments:

1. **Transport Security**: Layer the binary protocol over **TLS 1.3**, **DTLS**, or **Noise Protocol Framework** to provide confidentiality and authentication.
2. **Sequence Tracking**: Enforce a sliding sequence window at the receiver to drop replayed frames.
3. **Session Binding**: Validate `session_id` against active cryptographic session state tables.
