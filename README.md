# gen_protocol.py — Random C Protocol & IDL Compiler (VIQ)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![C Standard](https://img.shields.io/badge/c-C99%20%2F%20C11-green.svg)](https://en.wikipedia.org/wiki/C99)
[![Formal Verification](https://img.shields.io/badge/verification-SPIN%20BMC-purple.svg)](https://spinroot.com/)
[![IDL Specification](https://img.shields.io/badge/IDL-YAML%20%2F%20JSON-orange.svg)](https://yaml.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**gen_protocol.py** is a high-performance **binary protocol generator and IDL compiler** for C. It produces cryptographically seeded, collision-resistant C binary protocols or compiles declarative **YAML/JSON IDL** schemas into portable C headers (`.h`), implementation stubs (`.c`), formal **Promela SPIN** verification models (`.pml`), machine-readable manifests (`.json`), and human-readable **RFC Markdown specifications** (`PROTOCOL_SPEC.md`).

---

## 📐 Pipeline Architecture

```text
       Declarative Spec                    Random Spec Generator
       (protocol.yaml)                     (Cryptographic Seed)
              │                                      │
              └──────────────────┬───────────────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │   gen_protocol.py     │
                     │  Protocol Compiler    │
                     └───────────┬───────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
   C Header/Source         Promela Model             Markdown Spec
  (c_codegen .h/.c)      (pml_gen + SPIN)            (doc_gen .md)
```

---

## ⚡ Key Features & Safety Guarantees

| Feature | Description & Implementation Guarantees |
|---------|------------------------------------------|
| **22-Byte Frame Header** | Fixed 22-byte canonical wire header (`magic`, `version`, `opcode`, `session_id`, `sequence`, `payload_len`, `crc32`). |
| **Declarative IDL** | Import and compile custom protocol definitions from **YAML** (`protocol.yaml`) or **JSON** schemas via `--spec`. |
| **Formal Verification** | Auto-generates **Promela SPIN (`.pml`)** models and executes **Bounded Model Checking (BMC)** with 100% state reachability. |
| **Portable Byte-Swapping** | Zero-dependency byte swapping (`TO_WIRE16/32/64`, `FROM_WIRE16/32/64`) for `little-endian` and `big-endian` wire order. |
| **IEEE-754 Safety** | UB-free `float` and `double` wire encoding using `memcpy` bit re-interpretation + byte swapping. |
| **Bitfields & Arrays** | Portable integer storage with auto-generated bitmask getters/setters (`GET_*`, `SET_*`) and fixed array support. |
| **Frame CRC Integrity** | CRC-32/ISO-HDLC computed over `header(crc=0) || payload`. Internal double-swap protection built into `frame_crc()`. |
| **Validation Error Enum** | Explicit header validation error codes (`MY_PROTO_HDR_ERR_*`) returnable by `hdr_validate()`. |
| **Markdown Documentation** | Generates human-readable RFC-style specifications (`PROTOCOL_SPEC.md`) with ASCII header diagrams and opcode tables. |

---

## 📊 Wire Header Format (22 Octets)

All frames transmitted over the wire begin with the fixed 22-byte header:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            magic                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            version            |            opcode             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          session_id                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           sequence                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          payload_len          |             crc32             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            crc32 (cont)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset (Bytes) | Field Name | C Type | Wire Size | Description |
|---|---|---|---|---|
| `0 .. 3` | `magic` | `uint32_t` | 4 octets | Protocol identification constant (`0x...`) |
| `4 .. 5` | `version` | `uint16_t` | 2 octets | Encoded Major.Minor version (`(major << 8) \| minor`) |
| `6 .. 7` | `opcode` | `uint16_t` | 2 octets | Message opcode identifier |
| `8 .. 11` | `session_id` | `uint32_t` | 4 octets | Session or connection identifier |
| `12 .. 15` | `sequence` | `uint32_t` | 4 octets | Monotonic frame sequence counter |
| `16 .. 17` | `payload_len` | `uint16_t` | 2 octets | Payload byte length |
| `18 .. 21` | `crc32` | `uint32_t` | 4 octets | Frame CRC-32 (ISO-HDLC polynomial `0xEDB88320`) |

---

## 🚀 Quick Start

```bash
# 1. Generate a fully random protocol with SPIN verification, YAML IDL export, and Markdown spec
python3 gen_protocol.py -n MY_PROTO -p rpc --spin --export-spec --doc

# 2. Compile C code and Promela verification model from a declarative protocol.yaml IDL
python3 gen_protocol.py --spec protocol.yaml --spin -o out/my_proto_compiled

# 3. Reproduce a past run via seed
python3 gen_protocol.py --seed 807d5084d2da4e06178c1062a4ef9abd --spin

# 4. List past seed history
python3 gen_protocol.py --list-seeds
```

---

## 🛠️ CLI Options Reference

| Flag | Long Flag | Description | Default / Range |
|------|-----------|-------------|-----------------|
| `-o` | `--output DIR` | Output directory | `./out/<proto_name>/` |
| `-n` | `--name NAME` | Force protocol name prefix (sanitized) | Random |
| `-m` | `--messages N` | Number of message types | `4–16` (range `1–254`) |
| `-f` | `--fields N` | Max fields per struct | `3–10` (range `1–64`) |
| `-p` | `--pattern P` | Protocol pattern (`auto`, `reqrsp`, `stream`, `pubsub`, `rpc`, `fsm`) | `auto` |
| | `--spec FILE` | Compile protocol from YAML or JSON IDL specification | — |
| | `--export-spec`| Export declarative `protocol.yaml` IDL specification | `off` |
| | `--doc` | Generate human-readable `PROTOCOL_SPEC.md` documentation | `off` |
| | `--spin` | Generate Promela model and run SPIN formal verification | `off` |
| | `--no-verify` | Generate Promela `.pml` file but skip running SPIN | `off` |
| | `--no-impl` | Skip emitting `.c` implementation stub | `off` |
| | `--seed HEX` | Reproduce a previous run (32 hex characters) | — |
| | `--list-seeds` | Print seed log and exit | `off` |
| | `--json` | Emit machine-readable `manifest.json` | `off` |
| `-v` | `--verbose` | Print generated code to stdout | `off` |

---

## 📝 Declarative IDL Format (`protocol.yaml`)

```yaml
protocol:
  name: MY_PROTO
  version: 1.2.0
  endian: little        # little | big
  pattern: rpc          # reqrsp | stream | pubsub | rpc | fsm
  description: "Custom binary RPC protocol"

enums:
  - name: MY_PROTO_STATUS_t
    members:
      - { name: MY_PROTO_STATUS_OK, value: 0 }
      - { name: MY_PROTO_STATUS_ERR, value: 1 }

messages:
  - name: CONNECT
    opcode: 0x0001
    direction: C->S     # C->S | S->C | BIDI
    description: "Client connection request"
    fields:
      - { name: client_id, type: u32, comment: "Client unique integer ID" }
      - { name: flags, type: u8, bits: 4, comment: "Client operational flags" }
      - { name: buffer, type: u8, array_size: 64, comment: "Payload buffer" }

  - name: DISCONNECT
    opcode: 0x0002
    direction: C->S
    description: "Gracefully disconnect client"
    fields:
      - { name: reason, type: u8, comment: "Reason code for disconnection" }
```

---

## 💻 C API & Usage Example

```c
#include "my_proto.h"
#include <stdio.h>
#include <assert.h>

void send_frame(uint16_t opcode, uint32_t session_id, uint32_t sequence) {
    // 1. Initialise header (Host byte order)
    my_proto_hdr_t hdr;
    my_proto_msg_connect_t payload;
    
    payload.client_id = 1001;
    payload.flags = 0x05;
    
    // Encode payload fields to wire byte order
    my_proto_msg_connect_encode(&payload);

    my_proto_hdr_init(&hdr, opcode, session_id, sequence, sizeof(payload));

    // 2. Compute frame CRC (takes host header, converts to wire order with crc=0)
    hdr.crc32 = my_proto_frame_crc(&hdr, &payload, sizeof(payload));

    // 3. Convert header to wire byte order
    my_proto_hdr_encode(&hdr);

    // Send over socket/wire
    // send_bytes(&hdr, sizeof(hdr));
    // send_bytes(&payload, sizeof(payload));
}

void receive_frame(const my_proto_hdr_t *wire_hdr, const void *wire_payload, size_t payload_len) {
    // 1. Decode header to Host byte order
    my_proto_hdr_t hdr = *wire_hdr;
    my_proto_hdr_decode(&hdr);

    // 2. Validate header, magic, version, payload bounds, opcode, and CRC-32
    int status = my_proto_hdr_validate(&hdr, wire_payload, payload_len);
    if (status != MY_PROTO_HDR_OK) {
        // Error handling based on my_proto_hdr_err_t enum
        printf("Validation error: %d\n", status);
        return;
    }

    // 3. Decode message payload
    if (hdr.opcode == MY_PROTO_MSG_CONNECT) {
        my_proto_msg_connect_t payload;
        memcpy(&payload, wire_payload, sizeof(payload));
        my_proto_msg_connect_decode(&payload);
        printf("Received CONNECT from client %u\n", payload.client_id);
    }
}
```

---

## 🚨 Header Validation Error Codes (`my_proto_hdr_err_t`)

| Return Code | Macro Constant | Description |
|---|---|---|
| `0` | `MY_PROTO_HDR_OK` | Frame header and payload are valid. |
| `-1` | `MY_PROTO_HDR_ERR_MAGIC` | Invalid magic constant (`magic != MY_PROTO_MAGIC`). |
| `-2` | `MY_PROTO_HDR_ERR_VERSION` | Version mismatch (`version != MY_PROTO_VERSION`). |
| `-3` | `MY_PROTO_HDR_ERR_PAYLOAD_TOO_BIG` | Payload length exceeds `MY_PROTO_MAX_PAYLOAD`. |
| `-4` | `MY_PROTO_HDR_ERR_LEN_MISMATCH` | Payload buffer length mismatch. |
| `-5` | `MY_PROTO_HDR_ERR_CRC` | Frame CRC-32 checksum mismatch. |
| `-6` | `MY_PROTO_HDR_ERR_OPCODE` | Opcode is unknown or unsupported. |

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.
