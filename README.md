# gen_protocol.py — Random C Protocol & MultiChain Compiler (VIQ)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![C Standard](https://img.shields.io/badge/c-C99%20%2F%20C11-green.svg)](https://en.wikipedia.org/wiki/C99)
[![Formal Verification](https://img.shields.io/badge/verification-SPIN%20BMC-purple.svg)](https://spinroot.com/)
[![Architecture](https://img.shields.io/badge/architecture-DDD%20%2F%20Hexagonal-blueviolet.svg)](docs/MULTICHAIN_GUIDE.md)
[![IDL Specification](https://img.shields.io/badge/IDL-YAML%20%2F%20JSON-orange.svg)](https://yaml.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**gen_protocol.py** is a high-performance **binary protocol generator, MultiChain suite builder, and IDL compiler** for C, structured on **Domain-Driven Design (DDD) & Hexagonal Architecture**. 

It produces cryptographically seeded C binary protocols, multi-node **MultiChain interconnected network suites**, or compiles declarative **YAML/JSON IDL** schemas into portable C headers (`.h`), implementation stubs (`.c`), formal **Promela SPIN** verification models (`.pml`), machine-readable manifests (`.json`), and human-readable **RFC Markdown specifications** (`PROTOCOL_SPEC.md` / `MULTICHAIN_SPEC.md`).

---

## 📐 Domain-Driven Hexagonal Architecture

```text
               ┌───────────────────────────────────────────────┐
               │              CLI / Presentation               │
               │               (gen_protocol/cli)              │
               └───────────────────────┬───────────────────────┘
                                       │
                                       ▼
               ┌───────────────────────────────────────────────┐
               │           Application Service                 │
               │   (gen_protocol/application/compiler_service) │
               └──────┬─────────────────────────────────┬──────┘
                      │                                 │
                      ▼                                 ▼
   ┌────────────────────────────────────┐    ┌────────────────────────────────────┐
   │            Domain Layer            │    │            Adapters Layer          │
   │  - ProtocolGenerator               │    │  - CHeaderEmitter (.h)             │
   │  - MultiChainSuite entity          │    │  - CSourceEmitter (.c)             │
   │  - 22B Wire Header rules           │    │  - PromelaEmitter (.pml)           │
   │  - CRC-32 & Byte Swapping rules    │    │  - SpinVerifier (SPIN CLI)         │
   └────────────────────────────────────┘    └────────────────────────────────────┘
```

---

## ⚡ Key Features & Safety Guarantees

| Feature | Description & Implementation Guarantees |
|---------|------------------------------------------|
| **MultiChain Protocol Suites** | Generate $N$ interconnected protocols (`-c N` / `--multichain N`) with cross-chain bridge frame tunneling (`*_MSG_BRIDGE_TO_*`). |
| **22-Byte Frame Header** | Fixed 22-byte canonical wire header (`magic`, `version`, `opcode`, `session_id`, `sequence`, `payload_len`, `crc32`). |
| **HMAC-SHA256 Authentication** | Embedded zero-dependency FIPS 180-4 / RFC 2104 MAC authentication (`--auth hmac-sha256`) with constant-time verification. |
| **libFuzzer Harness & Corpus** | Standalone fuzz target generation (`--fuzz`) with automated seed corpus synthesis for continuous ASan/UBSan fuzzing. |
| **Declarative IDL** | Import and compile custom protocol definitions from **YAML** (`protocol.yaml`) or **JSON** schemas via `--spec`. |
| **Formal Verification** | Auto-generates **Promela SPIN (`.pml`)** models and executes **Bounded Model Checking (BMC)** with Dolev-Yao adversary verification. |
| **Portable Byte-Swapping** | Zero-dependency byte swapping (`TO_WIRE16/32/64`, `FROM_WIRE16/32/64`) for `little-endian` and `big-endian` wire order. |
| **IEEE-754 Safety** | UB-free `float` and `double` wire encoding using `memcpy` bit re-interpretation + byte swapping. |
| **Bitfields & Arrays** | Portable integer storage with auto-generated bitmask getters/setters (`GET_*`, `SET_*`) and fixed array support. |
| **Frame CRC Integrity** | CRC-32/ISO-HDLC computed over `header(crc=0) || payload`. Internal double-swap protection built into `frame_crc()`. |
| **Schema Length Validation** | `<proto>_expected_payload_len()` prevents truncated payload framing attacks (`HDR_ERR_LEN_SCHEMA`). |
| **Multi-Session Replay Table** | Built-in `<proto>_replay_table_t` with LRU eviction and IPsec-style sliding bitmap window protects against replay DoS. |
| **Validation Error Enum** | Explicit header validation error codes (`MY_PROTO_HDR_ERR_*`) returnable by `hdr_validate()`. |
| **Markdown Documentation** | Generates human-readable RFC-style specifications (`PROTOCOL_SPEC.md` / `MULTICHAIN_SPEC.md`). |

---

## 🌐 MultiChain Cross-Chain Network Topology

```text
[Node 1: Link 1] ──(Bridge Opcode 0x00FE)──> [Node 2: Link 2] ──(Bridge Opcode 0x00FE)──> ... ──> [Node N: Link N]
```

Each protocol link $L_i$ in a MultiChain suite includes an encapsulated tunnel bridge frame:
```c
typedef struct PROTO_PACKED {
    uint32_t     target_magic;         /* Magic constant of destination protocol */
    uint16_t     target_opcode;        /* Message opcode for target chain node */
    uint32_t     tunnel_seq;           /* Cross-chain tunnel sequence counter */
    uint8_t      tunnel_payload[1024]; /* Dynamically sized to encapsulate full target wire frame */
} chain_link_i_msg_bridge_to_chain_link_i_plus_1_t;
```

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

# 2. Generate a MultiChain suite of 5 interconnected protocols with cross-chain tunneling
python3 gen_protocol.py --multichain 5 --spin --doc --json

# 3. Compile C code and Promela verification model from a declarative protocol.yaml IDL
python3 gen_protocol.py --spec protocol.yaml --spin -o out/my_proto_compiled

# 4. Reproduce a past run via seed
python3 gen_protocol.py --seed 807d5084d2da4e06178c1062a4ef9abd --spin

# 5. List past seed history
python3 gen_protocol.py --list-seeds
```

---

## 🛠️ CLI Options Reference

| Flag | Long Flag | Description | Default / Range |
|------|-----------|-------------|-----------------|
| `-o` | `--output DIR` | Output directory | `./out/<proto_name>/` |
| `-n` | `--name NAME` | Force protocol name prefix (sanitized) | Random |
| `-c` | `--multichain N`, `--chains N` | Generate a MultiChain suite of N interconnected protocols | `1–32` |
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
```

---

## 📖 Additional Documentation

For deep technical details on multi-hop cross-chain data transmission, Promela LTL claims, security threat vectors, and theoretical state space limits, see:
- [MultiChain Technical Guide](docs/MULTICHAIN_GUIDE.md)
- [Protocol Security & Threat Matrix Assessment](docs/THREAT_MATRIX.md)
- [Theoretical Limits & Combinatorial Entropy Proof](docs/ENTROPY_AND_COMBINATORICS.md)

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.
