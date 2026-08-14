"""
Adapter emitting libFuzzer harness and valid seed corpus generator for protocol fuzzing.
"""

import os
import struct
from pathlib import Path
from typing import List

from gen_protocol.domain.models import Message, Protocol
from gen_protocol.domain.rules import calculate_magic
from gen_protocol.ports.emitter import CodeEmitter


class FuzzHarnessEmitter(CodeEmitter):
    def emit(self) -> str:
        p = self.p
        pname = p.name
        n = pname.lower()
        hdr_struct = p.header_struct_name

        cases = []
        for m in p.messages:
            mname = m.name.lower()
            cases.append(f"""        case {m.name}: {{
            {mname}_t msg;
            if (payload_len == sizeof(msg)) {{
                memcpy(&msg, payload, sizeof(msg));
                {mname}_decode(&msg);
                {mname}_encode(&msg);
            }}
            break;
        }}""")

        cases_str = "\n".join(cases)

        return f"""/*
 * =========================================================================
 *  Protocol Fuzzing Harness for {pname}
 *
 *  Engine: libFuzzer + ASan + UBSan
 *  Compile:
 *    clang -fsanitize=fuzzer,address,undefined -O2 -o {n}_fuzz \\
 *          {n}_fuzz.c {n}.c
 *
 *  Run:
 *    ./{n}_fuzz corpus/ -max_len={p.max_payload_size + 64} -timeout=10
 * =========================================================================
 */

#include "{n}.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (!data || size < sizeof({hdr_struct})) {{
        return 0; /* Input smaller than fixed wire header */
    }}

    {hdr_struct} hdr;
    memcpy(&hdr, data, sizeof(hdr));

    /* Decode wire header into host order */
    {n}_hdr_decode(&hdr);

    const uint8_t *payload = data + sizeof({hdr_struct});
    size_t payload_len = size - sizeof({hdr_struct});

    /* Validate frame header invariants, CRC, schema payload bounds */
    int res = {n}_hdr_validate(&hdr, payload, payload_len);
    if (res != {pname}_HDR_OK) {{
        return 0;
    }}

    /* Dispatch payload decoding and round-trip encode */
    switch (hdr.opcode) {{
{cases_str}
        default:
            break;
    }}

#if defined({pname}_AUTH_ENABLED)
    /* Test MAC verification if authentication is enabled */
    static const uint8_t fuzz_key[32] = "01234567890123456789012345678901";
    uint8_t mac_tag[32];
    {n}_frame_mac(&hdr, payload, payload_len, fuzz_key, sizeof(fuzz_key), mac_tag);
    (void){n}_mac_verify(&hdr, payload, payload_len, mac_tag, fuzz_key, sizeof(fuzz_key));
#endif

    return 0;
}}
"""


def generate_seed_corpus(proto: Protocol, corpus_dir: Path) -> List[Path]:
    """Generate a corpus of valid binary serialized frames for each message opcode."""
    corpus_dir.mkdir(parents=True, exist_ok=True)
    generated_files = []

    for idx, msg in enumerate(proto.messages, start=1):
        # Build raw payload bytes
        from gen_protocol.domain.rules import field_wire_size
        payload_size = sum(field_wire_size(f) for f in msg.fields)
        # Deterministic payload fill pattern
        raw_payload = bytearray(( (i * 37 + idx * 13) & 0xFF ) for i in range(payload_size))

        # Compute ISO-HDLC CRC32 over wire header (with crc32=0) + payload
        # Wire header format: magic(u32), version(u16), opcode(u16), session_id(u32), sequence(u32), payload_len(u16), crc32(u32)
        v_enc = ((proto.version_major & 0xFF) << 8) | (proto.version_minor & 0xFF)
        session_id = 0x10000000 + idx
        seq = idx

        fmt_endian = "<" if proto.endian == "little" else ">"
        hdr_zero_crc = struct.pack(
            f"{fmt_endian}IHHIIHI",
            proto.magic,
            v_enc,
            msg.opcode,
            session_id,
            seq,
            payload_size,
            0
        )

        import zlib
        # Ethernet / HDLC standard CRC32
        crc_val = zlib.crc32(hdr_zero_crc + raw_payload) & 0xFFFFFFFF

        hdr_wire = struct.pack(
            f"{fmt_endian}IHHIIHI",
            proto.magic,
            v_enc,
            msg.opcode,
            session_id,
            seq,
            payload_size,
            crc_val
        )

        frame = hdr_wire + raw_payload

        # If HMAC authentication is enabled, append 32-byte HMAC tag
        if proto.auth == "hmac-sha256":
            import hmac
            import hashlib
            key = b"01234567890123456789012345678901"
            mac = hmac.new(key, hdr_zero_crc + raw_payload, hashlib.sha256).digest()
            frame += mac

        bin_file = corpus_dir / f"seed_{msg.name.lower()}.bin"
        bin_file.write_bytes(frame)
        generated_files.append(bin_file)

    return generated_files
