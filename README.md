# gen_protocol.py — Random C Protocol VIQ Generator

Generates **cryptographically seeded, collision-resistant unique C protocols** per
invocation. Every run produces a distinct protocol name, magic constant,
version, field layout, opcode table, byte-swap macros, Promela model, and CRC-32 implementation.

## Key Features & Architecture

| Layer | Implementation & Safety Guarantees |
|-------|------------------------------------|
| Seed | `secrets.token_bytes(16)` + `uuid.uuid4()` + epoch timestamp → SHA-256 |
| Name | Sanitized via `_sanitize_proto_name()` (C reserved keywords & invalid chars safe) |
| Magic | SHA-256(name + seed) → 32-bit, zero-bytes patched |
| Endianness | Wire order (`little` or `big`) with `hdr_encode()` / `hdr_decode()` & compile-time `_PROTO_HOST_IS_BE` |
| Bitfields | Portable: full-width storage + auto-generated `GET_*` / `SET_*` bitmask accessors |
| Floating Point | Portable IEEE-754 conversion helpers (`_proto_f32_to_u32`, `_proto_u64_to_f64`) |
| Frame CRC | Chained CRC-32/ISO-HDLC over zeroed-CRC header + payload (`frame_crc()`) |
| Opcode Validation | Checked against generated opcode table in `hdr_validate()` (returns `-6` on unknown) |
| Formal Model | Promela SPIN model (`.pml`) with automated safety (`-DSAFETY`) & liveness (`-a`) verification |
| CLI Safety | Strict input validation for `-m 1..254` and `-f 1..64` |

## Quick start

```bash
python3 gen_protocol.py                         # fully random
python3 gen_protocol.py -n MY_PROTO -m 8 -f 5   # named, 8 msgs, max 5 fields
python3 gen_protocol.py -p rpc --spin --json     # RPC pattern + SPIN verification + JSON
python3 gen_protocol.py --seed fd11a289...       # reproduce a past run
python3 gen_protocol.py --list-seeds             # show seed log
```

## CLI options

| Flag | Description | Default / Range |
|------|-------------|-----------------|
| `-o DIR` | Output directory | `./out/<proto_name>/` |
| `-n NAME` | Force protocol name prefix (sanitized) | random |
| `-m N` | Number of message types | `4–16` (range `1–254`) |
| `-f N` | Max fields per struct | `3–10` (range `1–64`) |
| `-p PATTERN` | `auto` `reqrsp` `stream` `pubsub` `rpc` `fsm` | `auto` |
| `--spin` | Generate Promela model and run SPIN verification | off |
| `--no-verify` | With `--spin`: generate `.pml` but skip SPIN run | off |
| `--no-impl` | Skip `.c` stub | off |
| `--seed HEX` | Reproduce a previous run | — |
| `--list-seeds` | Print all past seeds | — |
| `--json` | Emit machine-readable JSON manifest | off |
| `-v` | Print generated code to stdout | off |

## API & Usage Example

```c
#include "my_proto.h"

// 1. Initialise header (host byte order)
my_proto_hdr_t hdr;
my_proto_hdr_init(&hdr, MY_PROTO_MSG_CONNECT, session_id, sequence_num, payload_len);

// 2. Compute frame CRC (chains header + payload in one pass)
hdr.crc32 = my_proto_frame_crc(&hdr, payload_buf, payload_len);

// 3. Convert multi-byte fields to wire byte order before sending
my_proto_hdr_encode(&hdr);
send_bytes(&hdr, sizeof(hdr));
send_bytes(payload_buf, payload_len);

// --- Receiver side ---
recv_bytes(&hdr, sizeof(hdr));

// 4. Decode wire byte order back to host order
my_proto_hdr_decode(&hdr);

// 5. Validate magic, version, payload length, CRC, and opcode
int status = my_proto_hdr_validate(&hdr, payload_buf, payload_len);
if (status != 0) {
    // Handling error (-1: bad magic, -2: ver, -3: pay_len, -4: len_mismatch, -5: crc, -6: opcode)
}
```

