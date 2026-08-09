# gen_protocol.py — Random C Protocol VIQ Generator

Generates **100% unique** C protocol headers and implementation stubs per
invocation. Every run produces a different protocol name, magic constant,
version, field layout, opcode table, and CRC-32 implementation.

## Uniqueness mechanism

| Layer | Technique |
|-------|-----------|
| Seed  | `secrets.token_bytes(16)` + `uuid.uuid4()` + epoch timestamp → SHA-256 |
| Name  | Drawn from 40 nouns × 20 suffixes |
| Magic | SHA-256(name + seed) → 32-bit, zero-bytes patched |
| Fields| Weighted random C type selection across 11 types |
| Reproducibility | Pass `--seed <HEX>` to replay any run exactly |

## Quick start

```bash
python3 gen_protocol.py                         # fully random
python3 gen_protocol.py -n MY_PROTO -m 8 -f 5  # forced name, 8 msgs, max 5 fields
python3 gen_protocol.py -p fsm --json           # FSM pattern + JSON manifest
python3 gen_protocol.py --seed fd11a289...      # reproduce a past run
python3 gen_protocol.py --list-seeds            # show all past seeds
```

## CLI options

| Flag | Description | Default |
|------|-------------|---------|
| `-o DIR` | Output directory | `./out/<proto_name>/` |
| `-n NAME` | Force protocol name prefix | random |
| `-m N` | Number of message types | 4–16 |
| `-f N` | Max fields per struct | 3–10 |
| `-p PATTERN` | `auto` `reqrsp` `stream` `pubsub` `rpc` `fsm` | `auto` |
| `--no-impl` | Skip `.c` stub | off |
| `--seed HEX` | Reproduce a previous run | — |
| `--list-seeds` | Print all past seeds | — |
| `--json` | Also emit JSON manifest | off |
| `-v` | Print generated code to stdout | off |

## Output files

```
out/<proto_name>/
  <proto_name>.h            ← packed structs, #defines, enums, API prototypes
  <proto_name>.c            ← CRC-32 table, hdr_init, hdr_validate, opcode_str
  <proto_name>_manifest.json ← machine-readable protocol manifest (with --json)
```

## Generated protocol structure

### Wire header (every frame)
```c
typedef struct __attribute__((packed)) {
    uint32_t magic;        // protocol magic constant
    uint32_t version;      // major.minor.patch packed
    uint8_t  opcode;       // one of MSG_* constants
    uint8_t  flags;
    uint16_t payload_len;
    uint32_t seq;          // monotonic counter
    uint32_t session_id;
    uint32_t crc32;        // CRC-32/ISO-HDLC of hdr(crc=0) + payload
} <proto>_hdr_t;
```

### Per-message payload structs
Each generated message gets a unique packed struct with 1–N typed fields,
optional bitfields, and optional fixed-size byte arrays.

### Enumerations
- `DIRECTION_t` — frame direction
- `ERR_t`       — protocol error codes
- `STATE_t`     — state-machine states (extended for FSM pattern)

### API
```c
void     <proto>_hdr_init(hdr, opcode, sess_id, pay_len);
int      <proto>_hdr_validate(hdr, payload, pay_len);   // -1…-5 on error
uint32_t <proto>_crc32(data, len);
const char *<proto>_opcode_str(opcode);
```

## Protocol patterns

| Pattern | Description |
|---------|-------------|
| `reqrsp` | Request/response — client sends, server replies |
| `stream` | Streaming — continuous unidirectional data flow |
| `pubsub` | Publish/subscribe — broker-mediated topic dispatch |
| `rpc`    | Remote Procedure Call — typed method invocation |
| `fsm`    | State-machine — strict phase transitions enforced |

## Seed log

Every run appends to `.protocol_seeds.jsonl`:
```json
{"ts": "2026-08-09T20:55:07Z", "seed": "fd11a289...", "name": "ARGON_GATE"}
```
