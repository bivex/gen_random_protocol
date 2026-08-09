# gen_protocol.py — Random C Protocol VIQ Generator

Generates **independently randomized, collision-resistant C protocols** with cryptographically seeded variation. Every run produces a distinct protocol name, magic constant, version, field layout, opcode table, byte-swap macros, Promela model, and CRC-32 implementation.

## Key Features & Architecture

| Layer | Implementation & Safety Guarantees |
|-------|------------------------------------|
| Seed | `secrets.token_bytes(16)` + `uuid.uuid4()` + epoch timestamp → 32-char hex seed |
| Name | Sanitized via `_sanitize_proto_name()` (C reserved keywords & invalid chars safe) |
| Magic | SHA-256(name + seed) → 32-bit, zero-bytes patched |
| Endianness | Wire order (`little` or `big`) for common header and per-message payload structs (`<msg>_encode`, `<msg>_decode`) |
| Bitfields | Portable: full-width storage + auto-generated `GET_*` / `SET_*` bitmask accessors |
| Floating Point | Portable IEEE-754 conversion helpers (`_proto_f32_to_u32`, `_proto_u64_to_f64`) + wire byte-swapping |
| Boolean Type | Explicit 1-octet wire format (`uint8_t`: 0 = false, 1 = true) |
| Frame CRC | CRC-32/ISO-HDLC computed over **exact wire-encoded bytes** (`wire_hdr(crc=0) || wire_payload`) |
| Opcode Validation | Checked against generated opcode table in `hdr_validate()` (returns `-6` on unknown) |
| Formal Model | Promela SPIN model (`.pml`) performing **Bounded Model Checking (BMC)** up to `MAX_ITER = 16` |
| Manifest | JSON manifest with exact per-field and per-message payload `wire_size` in bytes |
| CLI Safety | Strict input validation for `-m 1..254`, `-f 1..64`, and `--seed` (32-character hex) |

## Quick start

```bash
python3 gen_protocol.py                         # fully random
python3 gen_protocol.py -n MY_PROTO -m 8 -f 5   # named, 8 msgs, max 5 fields
python3 gen_protocol.py -p rpc --spin --json     # RPC pattern + SPIN verification + JSON
python3 gen_protocol.py --seed 3e8c4ea8...       # reproduce a past run
python3 gen_protocol.py --list-seeds             # show seed log
```

## CLI options

| Flag | Description | Default / Range |
|------|-------------|-----------------|
| `-o DIR` | Output directory | `./out/<proto_name>/` |
| `-n NAME` | Force protocol name prefix (sanitized) | random |
| `-m N` | Number of message types | `4–16` (range `1–254`) |
| `-f N` | Max fields per struct (including injected) | `3–10` (range `1–64`) |
| `-p PATTERN` | `auto` `reqrsp` `stream` `pubsub` `rpc` `fsm` | `auto` |
| `--spin` | Generate Promela model and run SPIN verification | off |
| `--no-verify` | With `--spin`: generate `.pml` but skip SPIN run | off |
| `--no-impl` | Skip `.c` stub | off |
| `--seed HEX` | Reproduce a previous run (32 hex chars) | — |
| `--list-seeds` | Print all past seeds | — |
| `--json` | Emit machine-readable JSON manifest | off |
| `-v` | Print generated code to stdout | off |

## API & Usage Example

```c
#include "my_proto.h"

// 1. Initialise header (host byte order)
my_proto_hdr_t hdr;
my_proto_hdr_init(&hdr, MY_PROTO_MSG_CONNECT, session_id, sequence_num, payload_len);

// 2. Prepare payload & encode payload fields to wire byte order
my_proto_msg_connect_t payload;
// ... fill payload fields ...
my_proto_msg_connect_encode(&payload);

// 3. Compute frame CRC over wire-encoded header (crc=0) + wire payload bytes
hdr.crc32 = my_proto_frame_crc(&hdr, &payload, sizeof(payload));

// 4. Convert header multi-byte fields to wire byte order
my_proto_hdr_encode(&hdr);
send_bytes(&hdr, sizeof(hdr));
send_bytes(&payload, sizeof(payload));

// --- Receiver side ---
recv_bytes(&hdr, sizeof(hdr));

// 5. Decode wire header back to host order
my_proto_hdr_decode(&hdr);

// 6. Validate magic, version, payload length, CRC (computed on wire bytes), and opcode
int status = my_proto_hdr_validate(&hdr, wire_payload_buf, payload_len);
if (status != 0) {
    // Error handling (-1: magic, -2: ver, -3: pay_len, -4: len_mismatch, -5: crc, -6: opcode)
}

// 7. Decode wire payload fields back to host byte order
recv_bytes(&payload, sizeof(payload));
my_proto_msg_connect_decode(&payload);
```


