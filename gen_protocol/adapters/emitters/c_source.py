"""
Adapter emitting C Source (.c) implementation files.
"""

from gen_protocol.domain.models import Field, Message, Protocol
from gen_protocol.ports.emitter import CodeEmitter


class CSourceEmitter(CodeEmitter):
    def _swap_stmt(self, ctype: str, expr: str, is_encode: bool) -> str:
        pname = self.p.name
        direction = "TO" if is_encode else "FROM"
        swaps = {
            "uint16_t": f"{pname}_{direction}_WIRE16({expr})",
            "int16_t":  f"(int16_t){pname}_{direction}_WIRE16({expr})",
            "uint32_t": f"{pname}_{direction}_WIRE32({expr})",
            "int32_t":  f"(int32_t){pname}_{direction}_WIRE32({expr})",
            "uint64_t": f"{pname}_{direction}_WIRE64({expr})",
            "int64_t":  f"(int64_t){pname}_{direction}_WIRE64({expr})",
        }
        if ctype in swaps:
            return f"{expr} = {swaps[ctype]};"
        elif ctype == "float":
            fn_to = "proto_f32_to_u32_"
            fn_from = "proto_u32_to_f32_"
            return (
                f"{expr} = {fn_from}({pname}_{direction}_WIRE32({fn_to}({expr})));"
            )
        elif ctype == "double":
            fn_to = "proto_f64_to_u64_"
            fn_from = "proto_u64_to_f64_"
            return (
                f"{expr} = {fn_from}({pname}_{direction}_WIRE64({fn_to}({expr})));"
            )
        return ""

    def _field_swap_lines(self, f: Field, is_encode: bool, indent: str = "    ") -> list[str]:
        lines = []
        if f.array_size is not None:
            stmt = self._swap_stmt(f.ctype, f"msg->{f.name}[i]", is_encode)
            if stmt:
                lines += [
                    f"{indent}for (size_t i = 0; i < {f.array_size}U; i++) {{",
                    f"{indent}    {stmt}",
                    f"{indent}}}",
                ]
        else:
            stmt = self._swap_stmt(f.ctype, f"msg->{f.name}", is_encode)
            if stmt:
                lines.append(f"{indent}{stmt}")
        return lines

    def _payload_serialization_code(self) -> str:
        pname = self.p.name
        blocks = []
        for msg in self.p.messages:
            mname = msg.name.lower()
            enc_lines = []
            dec_lines = []
            for f in msg.fields:
                enc_lines.extend(self._field_swap_lines(f, is_encode=True))
                dec_lines.extend(self._field_swap_lines(f, is_encode=False))

            enc_body = "\n".join(enc_lines) if enc_lines else "    (void)msg; /* No multi-byte fields */"
            dec_body = "\n".join(dec_lines) if dec_lines else "    (void)msg; /* No multi-byte fields */"

            blocks.append("\n".join([
                f"void {mname}_encode({mname}_t *msg) {{",
                f"    if (!msg) return;",
                enc_body,
                f"}}",
                "",
                f"void {mname}_decode({mname}_t *msg) {{",
                f"    if (!msg) return;",
                dec_body,
                f"}}",
            ]))
        return "\n\n".join(blocks)

    def _opcode_map(self) -> str:
        pname = self.p.name
        lines = [
            f"const char *{pname.lower()}_opcode_str(uint16_t opcode) {{",
            f"    switch (opcode) {{",
        ]
        for m in self.p.messages:
            lines.append(f'        case {m.name}: return "{m.name}";')
        lines += [
            f'        default: return "UNKNOWN_OPCODE";',
            f"    }}",
            f"}}",
        ]
        return "\n".join(lines)

    def emit(self) -> str:
        p = self.p
        pname = p.name
        n = pname.lower()
        hdr_struct = p.header_struct_name
    def _expected_payload_len_func(self) -> str:
        p = self.p
        n = p.name.lower()
        lines = [
            f"uint16_t {n}_expected_payload_len(uint16_t opcode) {{",
            "    switch (opcode) {",
        ]
        for m in p.messages:
            lines.append(f"        case {m.name}: return (uint16_t)sizeof({m.name.lower()}_t);")
        lines += [
            "        default: return 0xFFFFU;",
            "    }",
            "}",
        ]
        return "\n".join(lines)

    def _auth_implementation(self) -> str:
        p = self.p
        if p.auth != "hmac-sha256":
            return ""
        pname = p.name
        n = p.name.lower()
        hdr_struct = p.header_struct_name

        return "\n".join([
            "/* === Portable Constant-Time Memory Compare === */",
            f"int {n}_const_time_memcmp(const void *a, const void *b, size_t len) {{",
            "    const volatile unsigned char *pa = (const volatile unsigned char *)a;",
            "    const volatile unsigned char *pb = (const volatile unsigned char *)b;",
            "    volatile unsigned char diff = 0;",
            "    for (size_t i = 0; i < len; i++) {",
            "        diff |= (pa[i] ^ pb[i]);",
            "    }",
            "    return (diff == 0) ? 0 : -1;",
            "}",
            "",
            "/* === Zero-Dependency Portable FIPS 180-4 SHA-256 Implementation === */",
            "typedef struct {",
            "    uint32_t state[8];",
            "    uint64_t count;",
            "    uint8_t  buffer[64];",
            f"}} {n}_sha256_ctx_t;",
            "",
            f"static inline uint32_t {n}_rotr32(uint32_t x, uint32_t n) {{",
            "    return (x >> n) | (x << (32 - n));",
            "}",
            "",
            f"static void {n}_sha256_transform({n}_sha256_ctx_t *ctx, const uint8_t data[64]) {{",
            "    static const uint32_t K[64] = {",
            "        0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,",
            "        0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,",
            "        0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,",
            "        0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,",
            "        0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,",
            "        0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,",
            "        0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,",
            "        0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,",
            "        0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,",
            "        0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,",
            "        0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,",
            "        0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,",
            "        0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,",
            "        0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,",
            "        0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,",
            "        0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U",
            "    };",
            "    uint32_t W[64];",
            "    for (int i = 0; i < 16; i++) {",
            "        W[i] = ((uint32_t)data[i * 4] << 24) |",
            "               ((uint32_t)data[i * 4 + 1] << 16) |",
            "               ((uint32_t)data[i * 4 + 2] << 8) |",
            "               ((uint32_t)data[i * 4 + 3]);",
            "    }",
            "    for (int i = 16; i < 64; i++) {",
            f"        uint32_t s0 = {n}_rotr32(W[i - 15], 7) ^ {n}_rotr32(W[i - 15], 18) ^ (W[i - 15] >> 3);",
            f"        uint32_t s1 = {n}_rotr32(W[i - 2], 17) ^ {n}_rotr32(W[i - 2], 19) ^ (W[i - 2] >> 10);",
            "        W[i] = W[i - 16] + s0 + W[i - 7] + s1;",
            "    }",
            "    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];",
            "    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];",
            "    for (int i = 0; i < 64; i++) {",
            f"        uint32_t S1 = {n}_rotr32(e, 6) ^ {n}_rotr32(e, 11) ^ {n}_rotr32(e, 25);",
            "        uint32_t ch = (e & f) ^ ((~e) & g);",
            "        uint32_t temp1 = h + S1 + ch + K[i] + W[i];",
            f"        uint32_t S0 = {n}_rotr32(a, 2) ^ {n}_rotr32(a, 13) ^ {n}_rotr32(a, 22);",
            "        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);",
            "        uint32_t temp2 = S0 + maj;",
            "        h = g; g = f; f = e; e = d + temp1;",
            "        d = c; c = b; b = a; a = temp1 + temp2;",
            "    }",
            "    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;",
            "    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;",
            "}",
            "",
            f"static void {n}_sha256_init({n}_sha256_ctx_t *ctx) {{",
            "    ctx->state[0] = 0x6A09E667U; ctx->state[1] = 0xBB67AE85U;",
            "    ctx->state[2] = 0x3C6EF372U; ctx->state[3] = 0xA54FF53AU;",
            "    ctx->state[4] = 0x510E527FU; ctx->state[5] = 0x9B05688CU;",
            "    ctx->state[6] = 0x1F83D9ABU; ctx->state[7] = 0x5BE0CD19U;",
            "    ctx->count = 0;",
            "}",
            "",
            f"static void {n}_sha256_update({n}_sha256_ctx_t *ctx, const void *data, size_t len) {{",
            "    const uint8_t *p = (const uint8_t *)data;",
            "    size_t buf_idx = (size_t)(ctx->count & 63ULL);",
            "    ctx->count += len;",
            "    while (len > 0) {",
            "        size_t to_copy = 64 - buf_idx;",
            "        if (to_copy > len) to_copy = len;",
            "        memcpy(ctx->buffer + buf_idx, p, to_copy);",
            "        p += to_copy;",
            "        len -= to_copy;",
            "        buf_idx += to_copy;",
            "        if (buf_idx == 64) {",
            f"            {n}_sha256_transform(ctx, ctx->buffer);",
            "            buf_idx = 0;",
            "        }",
            "    }",
            "}",
            "",
            f"static void {n}_sha256_final({n}_sha256_ctx_t *ctx, uint8_t digest[32]) {{",
            "    uint64_t bits = ctx->count * 8ULL;",
            "    size_t buf_idx = (size_t)(ctx->count & 63ULL);",
            "    ctx->buffer[buf_idx++] = 0x80;",
            "    if (buf_idx > 56) {",
            "        memset(ctx->buffer + buf_idx, 0, 64 - buf_idx);",
            f"        {n}_sha256_transform(ctx, ctx->buffer);",
            "        buf_idx = 0;",
            "    }",
            "    memset(ctx->buffer + buf_idx, 0, 56 - buf_idx);",
            "    for (int i = 7; i >= 0; i--) {",
            "        ctx->buffer[56 + (7 - i)] = (uint8_t)((bits >> (i * 8)) & 0xFF);",
            "    }",
            f"    {n}_sha256_transform(ctx, ctx->buffer);",
            "    for (int i = 0; i < 8; i++) {",
            "        digest[i * 4]     = (uint8_t)((ctx->state[i] >> 24) & 0xFF);",
            "        digest[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);",
            "        digest[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xFF);",
            "        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xFF);",
            "    }",
            "}",
            "",
            f"void {n}_frame_mac(const {hdr_struct} *hdr, const void *payload, size_t payload_len,",
            "                   const uint8_t *key, size_t key_len, uint8_t mac_out[32]) {",
            "    if (!hdr || !mac_out) return;",
            f"    {hdr_struct} wire_hdr = *hdr;",
            "    wire_hdr.crc32 = 0U; /* CRC field zeroed during MAC calculation */",
            f"    {n}_hdr_encode(&wire_hdr);",
            "",
            "    uint8_t k_pad[64];",
            "    memset(k_pad, 0, sizeof(k_pad));",
            "    if (key_len > 64) {",
            f"        {n}_sha256_ctx_t k_ctx;",
            f"        {n}_sha256_init(&k_ctx);",
            f"        {n}_sha256_update(&k_ctx, key, key_len);",
            f"        {n}_sha256_final(&k_ctx, k_pad);",
            "    } else {",
            "        if (key && key_len > 0) memcpy(k_pad, key, key_len);",
            "    }",
            "",
            "    uint8_t ipad[64], opad[64];",
            "    for (int i = 0; i < 64; i++) {",
            "        ipad[i] = k_pad[i] ^ 0x36;",
            "        opad[i] = k_pad[i] ^ 0x5C;",
            "    }",
            "",
            "    uint8_t inner_hash[32];",
            f"    {n}_sha256_ctx_t in_ctx;",
            f"    {n}_sha256_init(&in_ctx);",
            f"    {n}_sha256_update(&in_ctx, ipad, 64);",
            f"    {n}_sha256_update(&in_ctx, &wire_hdr, sizeof(wire_hdr));",
            "    if (payload && payload_len > 0) {",
            f"        {n}_sha256_update(&in_ctx, payload, payload_len);",
            "    }",
            f"    {n}_sha256_final(&in_ctx, inner_hash);",
            "",
            f"    {n}_sha256_ctx_t out_ctx;",
            f"    {n}_sha256_init(&out_ctx);",
            f"    {n}_sha256_update(&out_ctx, opad, 64);",
            f"    {n}_sha256_update(&out_ctx, inner_hash, 32);",
            f"    {n}_sha256_final(&out_ctx, mac_out);",
            "}",
            "",
            f"int {n}_mac_verify(const {hdr_struct} *hdr, const void *payload, size_t payload_len,",
            "                   const uint8_t *mac, const uint8_t *key, size_t key_len) {",
            f"    if (!hdr || !mac || !key) return {pname}_HDR_ERR_AUTH_FAIL;",
            "    uint8_t expected_mac[32];",
            f"    {n}_frame_mac(hdr, payload, payload_len, key, key_len, expected_mac);",
            f"    if ({n}_const_time_memcmp(expected_mac, mac, 32) != 0) {{",
            f"        return {pname}_HDR_ERR_AUTH_FAIL;",
            "    }",
            f"    return {pname}_HDR_OK;",
            "}",
            "",
        ])

    def _replay_table_code(self) -> str:
        pname = self.p.name
        n = pname.lower()
        return "\n".join([
            f"/* === Multi-Session Anti-Replay Table Implementation === */",
            f"void {n}_replay_table_init({n}_replay_table_t *tbl) {{",
            f"    if (!tbl) return;",
            f"    memset(tbl, 0, sizeof(*tbl));",
            f"}}",
            f"",
            f"static size_t {n}_replay_hash(uint32_t session_id) {{",
            f"    uint32_t x = session_id;",
            f"    x ^= x >> 16;",
            f"    x *= 0x45D9F3BU;",
            f"    x ^= x >> 16;",
            f"    return (size_t)(x % {pname}_REPLAY_TABLE_CAPACITY);",
            f"}}",
            f"",
            f"bool {n}_replay_table_check({n}_replay_table_t *tbl, uint32_t session_id, uint32_t seq) {{",
            f"    if (!tbl) return false;",
            f"    tbl->access_clock++;",
            f"    size_t start_idx = {n}_replay_hash(session_id);",
            f"    size_t free_idx = {pname}_REPLAY_TABLE_CAPACITY;",
            f"    size_t lru_idx = 0;",
            f"    uint32_t min_access = 0xFFFFFFFFU;",
            f"",
            f"    for (size_t step = 0; step < {pname}_REPLAY_TABLE_CAPACITY; step++) {{",
            f"        size_t idx = (start_idx + step) % {pname}_REPLAY_TABLE_CAPACITY;",
            f"        if (tbl->entries[idx].occupied) {{",
            f"            if (tbl->entries[idx].session_id == session_id) {{",
            f"                tbl->entries[idx].last_access = tbl->access_clock;",
            f"                return {n}_replay_check(&tbl->entries[idx].state, seq);",
            f"            }}",
            f"            if (tbl->entries[idx].last_access < min_access) {{",
            f"                min_access = tbl->entries[idx].last_access;",
            f"                lru_idx = idx;",
            f"            }}",
            f"        }} else if (free_idx == {pname}_REPLAY_TABLE_CAPACITY) {{",
            f"            free_idx = idx;",
            f"        }}",
            f"    }}",
            f"",
            f"    /* New session: allocate slot or evict LRU */",
            f"    size_t target = (free_idx != {pname}_REPLAY_TABLE_CAPACITY) ? free_idx : lru_idx;",
            f"    if (free_idx != {pname}_REPLAY_TABLE_CAPACITY) {{",
            f"        tbl->count++;",
            f"    }}",
            f"    tbl->entries[target].occupied = true;",
            f"    tbl->entries[target].session_id = session_id;",
            f"    tbl->entries[target].last_access = tbl->access_clock;",
            f"    memset(&tbl->entries[target].state, 0, sizeof(tbl->entries[target].state));",
            f"    return {n}_replay_check(&tbl->entries[target].state, seq);",
            f"}}",
        ])

    def emit(self) -> str:
        p = self.p
        pname = p.name
        n = pname.lower()
        hdr_struct = p.header_struct_name
        h_file = f"{n}.h"

        return "\n".join([
            f'#include "{h_file}"',
            "#include <string.h>",
            "",
            "/* ISO-HDLC / Ethernet CRC-32 lookup table (polynomial 0xEDB88320) */",
            "static const uint32_t PROTO_CRC32_TABLE[256] = {",
            "    0x00000000UL, 0x77073096UL, 0xEE0E612CUL, 0x990951BAUL, 0x076DC419UL, 0x706AF48FUL, 0xE963A535UL, 0x9E6495A3UL,",
            "    0x0EDB8832UL, 0x79DCB8A4UL, 0xE0D5E91EUL, 0x97D2D988UL, 0x09B64C2BUL, 0x7EB17CBDUL, 0xE7B82D07UL, 0x90BF1D91UL,",
            "    0x1DB71064UL, 0x6AB020F2UL, 0xF3B97148UL, 0x84BE41DEUL, 0x1ADAD47DUL, 0x6DDDE4EBUL, 0xF4D4B551UL, 0x83D385C7UL,",
            "    0x136C9856UL, 0x646BA8C0UL, 0xFD62F97AUL, 0x8A65C9ECUL, 0x14015C4FUL, 0x63066CD9UL, 0xFA0F3D63UL, 0x8D080DF5UL,",
            "    0x3B6E20C8UL, 0x4C69105EUL, 0xD56041E4UL, 0xA2677172UL, 0x3C03E4D1UL, 0x4B04D447UL, 0xD20D85FDUL, 0xA50AB56BUL,",
            "    0x35B5A8FAUL, 0x42B2986CUL, 0xDBBBC9D6UL, 0xACBCF940UL, 0x32D86CE3UL, 0x45DF5C75UL, 0xDCD60DCFUL, 0xABD13D59UL,",
            "    0x26D930ACUL, 0x51DE003AUL, 0xC8D75180UL, 0xBFD06116UL, 0x21B4F4B5UL, 0x56B3C423UL, 0xCFBA9599UL, 0xB8BDA50FUL,",
            "    0x2802B89EUL, 0x5F058808UL, 0xC60CD9B2UL, 0xB10BE924UL, 0x2F6F7C87UL, 0x58684C11UL, 0xC1611DABUL, 0xB6662D3DUL,",
            "    0x76DC4190UL, 0x01DB7106UL, 0x98D220BCUL, 0xEFD5102AUL, 0x71B18589UL, 0x06B6B51FUL, 0x9FBFE4A5UL, 0xE8B8D433UL,",
            "    0x7807C9A2UL, 0x0F00F934UL, 0x9609A88EUL, 0xE10E9818UL, 0x7F6A0DBBUL, 0x086D3D2DUL, 0x91646C97UL, 0xE6635C01UL,",
            "    0x6B6B51F4UL, 0x1C6C6162UL, 0x856530D8UL, 0xF262004EUL, 0x6C0695EDUL, 0x1B01A57BUL, 0x8208F4C1UL, 0xF50FC457UL,",
            "    0x65B0D9C6UL, 0x12B7E950UL, 0x8BBCE8EAUL, 0xFCBBBEDCUL, 0x62DD1DDFUL, 0x15DA2D49UL, 0x8CD37CF3UL, 0xFBD44C65UL,",
            "    0x4DB26158UL, 0x3AB551CEUL, 0xA3BC0074UL, 0xD4BB30E2UL, 0x4ADFA541UL, 0x3DD895D7UL, 0xA4D1C46DUL, 0xD3D6F4FBUL,",
            "    0x4369E96AUL, 0x346ED9FCUL, 0xAD678846UL, 0xDA60B8D0UL, 0x44042D73UL, 0x33031DE5UL, 0xAA0A4C5FUL, 0xDD0D7CC9UL,",
            "    0x5005713CUL, 0x270241AAUL, 0xBE0B1010UL, 0xC90C2086UL, 0x5768B525UL, 0x206F85B3UL, 0xB966D409UL, 0xCE61E49FUL,",
            "    0x5EDEF90EUL, 0x29D9C998UL, 0xB0D09822UL, 0xC7D7A8B4UL, 0x59B33D17UL, 0x2EB40D81UL, 0xB7BD5C3BUL, 0xC0BA6CADUL,",
            "    0xEDB88320UL, 0x9ABFB3B6UL, 0x03B6E20CUL, 0x74B1D29AUL, 0xEAD54739UL, 0x9DD277AFUL, 0x04DB2615UL, 0x73DC1683UL,",
            "    0xE3630B12UL, 0x94643B84UL, 0x0D6D6A3EUL, 0x7A6A5AA8UL, 0xE40ECF0BUL, 0x9309FF9DUL, 0x0A00AE27UL, 0x7D079EB1UL,",
            "    0xF00F9344UL, 0x8708A3D2UL, 0x1E01F268UL, 0x6906C2FEUL, 0xF762575DUL, 0x806567CBUL, 0x196C3671UL, 0x6E6B06E7UL,",
            "    0xFED41B76UL, 0x89D32BE0UL, 0x10DA7A5AUL, 0x67DD4ACCUL, 0xF9B9DF6FUL, 0x8EBEEFF9UL, 0x17B7BE43UL, 0x60B08ED5UL,",
            "    0xD6D6A3E8UL, 0xA1D1937EUL, 0x38D8C2C4UL, 0x4FDFF252UL, 0xD1BB67F1UL, 0xA6BC5767UL, 0x3FB506DDUL, 0x48B2364BUL,",
            "    0xD80D2BDAUL, 0xAF0A1B4CUL, 0x36034AF6UL, 0x41047A60UL, 0xDF60EFC3UL, 0xA867DF55UL, 0x316E8EEFUL, 0x4669BE79UL,",
            "    0xCB61B38CUL, 0xBC66831AUL, 0x256FD2A0UL, 0x5268E236UL, 0xCC0C7795UL, 0xBB0B4703UL, 0x220216B9UL, 0x5505262FUL,",
            "    0xC5BA3BBEUL, 0xB2BD0B28UL, 0x2BB45A92UL, 0x5CB36A04UL, 0xC2D7FFA7UL, 0xB5D0CF31UL, 0x2CD99E8BUL, 0x5BDEAE1DUL,",
            "    0x9B64C2B0UL, 0xEC63F226UL, 0x756AA39CUL, 0x026D930AUL, 0x9C0906A9UL, 0xEB0E363FUL, 0x72076785UL, 0x05005713UL,",
            "    0x95BF4A82UL, 0xE2B87A14UL, 0x7BB12BAEUL, 0x0CB61B38UL, 0x92D28E9BUL, 0xE5D5BE0DUL, 0x7CDCEFB7UL, 0x0BDBDF21UL,",
            "    0x86D3D2D4UL, 0xF1D4E242UL, 0x68DDB3F8UL, 0x1FDA836EUL, 0x81BE16CDUL, 0xF6B9265BUL, 0x6FB077E1UL, 0x18B74777UL,",
            "    0x88085AE6UL, 0xFF0F6A70UL, 0x66063BCAUL, 0x11010B5CUL, 0x8F659EFFUL, 0xF862AE69UL, 0x616BFFD3UL, 0x166CCF45UL,",
            "    0xA00AE278UL, 0xD70DD2EEUL, 0x4E048354UL, 0x3903B3C2UL, 0xA7672661UL, 0xD06016F7UL, 0x4969474DUL, 0x3E6E77DBUL,",
            "    0xAED16A4AUL, 0xD9D65ADCUL, 0x40DF0B66UL, 0x37D83BF0UL, 0xA9BCAE53UL, 0xDEBB9EC5UL, 0x47B2CF7FUL, 0x30B5FFE9UL,",
            "    0xBD5C3B1CUL, 0xCA5B0B8AUL, 0x53525A30UL, 0x24556AA6UL, 0xB551F705UL, 0xC256C793UL, 0x5B5FB629UL, 0x2C5886BFUL,",
            "    0xB387B70EUL, 0xC4808798UL, 0x5D89D622UL, 0x2A8EE6B4UL, 0xB40B7F07UL, 0xC30C4F91UL, 0x5A051E3BUL, 0x2D022EADUL,",
            "};",
            "",
            f"uint32_t {n}_crc32(const void *data, size_t len) {{",
            "    const uint8_t *p = (const uint8_t *)data;",
            "    uint32_t crc = 0xFFFFFFFFUL;",
            "    for (size_t i = 0; i < len; i++) {",
            "        crc = (crc >> 8) ^ PROTO_CRC32_TABLE[(crc ^ p[i]) & 0xFFU];",
            "    }",
            "    return crc ^ 0xFFFFFFFFUL;",
            "}",
            "",
            f"uint32_t {n}_frame_crc(const {hdr_struct} *hdr, const void *payload, size_t payload_len) {{",
            f"    /* Copy header, zero out crc32 field, and convert to wire order for CRC computation */",
            f"    {hdr_struct} tmp = *hdr;",
            "    tmp.crc32 = 0U;",
            f"    {n}_hdr_encode(&tmp);",
            "",
            f"    uint32_t crc = 0xFFFFFFFFUL;",
            "    const uint8_t *p = (const uint8_t *)&tmp;",
            f"    for (size_t i = 0; i < sizeof({hdr_struct}); i++) {{",
            "        crc = (crc >> 8) ^ PROTO_CRC32_TABLE[(crc ^ p[i]) & 0xFFU];",
            "    }",
            "    if (payload && payload_len > 0) {",
            "        p = (const uint8_t *)payload;",
            "        for (size_t i = 0; i < payload_len; i++) {",
            "            crc = (crc >> 8) ^ PROTO_CRC32_TABLE[(crc ^ p[i]) & 0xFFU];",
            "        }",
            "    }",
            "    return crc ^ 0xFFFFFFFFUL;",
            "}",
            "",
            self._expected_payload_len_func(),
            "",
            f"void {n}_hdr_init({hdr_struct} *hdr, uint16_t opcode,",
            f"                   uint32_t session_id, uint32_t sequence, uint16_t payload_len) {{",
            "    if (!hdr) return;",
            f"    hdr->magic       = {pname}_MAGIC;",
            f"    hdr->version     = {pname}_VERSION;",
            "    hdr->opcode      = opcode;",
            "    hdr->session_id  = session_id;",
            "    hdr->sequence    = sequence;",
            "    hdr->payload_len = payload_len;",
            "    hdr->crc32       = 0U;",
            "}",
            "",
            f"void {n}_hdr_encode({hdr_struct} *hdr) {{",
            "    if (!hdr) return;",
            f"    hdr->magic       = {pname}_TO_WIRE32(hdr->magic);",
            f"    hdr->version     = {pname}_TO_WIRE16(hdr->version);",
            f"    hdr->opcode      = {pname}_TO_WIRE16(hdr->opcode);",
            f"    hdr->session_id  = {pname}_TO_WIRE32(hdr->session_id);",
            f"    hdr->sequence    = {pname}_TO_WIRE32(hdr->sequence);",
            f"    hdr->payload_len = {pname}_TO_WIRE16(hdr->payload_len);",
            f"    hdr->crc32       = {pname}_TO_WIRE32(hdr->crc32);",
            "}",
            "",
            f"void {n}_hdr_decode({hdr_struct} *hdr) {{",
            "    if (!hdr) return;",
            f"    hdr->magic       = {pname}_FROM_WIRE32(hdr->magic);",
            f"    hdr->version     = {pname}_FROM_WIRE16(hdr->version);",
            f"    hdr->opcode      = {pname}_FROM_WIRE16(hdr->opcode);",
            f"    hdr->session_id  = {pname}_FROM_WIRE32(hdr->session_id);",
            f"    hdr->sequence    = {pname}_FROM_WIRE32(hdr->sequence);",
            f"    hdr->payload_len = {pname}_FROM_WIRE16(hdr->payload_len);",
            f"    hdr->crc32       = {pname}_FROM_WIRE32(hdr->crc32);",
            "}",
            "",
            f"int {n}_hdr_validate(const {hdr_struct} *hdr, const void *payload, size_t payload_len) {{",
            "    if (!hdr) return -1;",
            f"    if (hdr->magic != {pname}_MAGIC)                           return {pname}_HDR_ERR_MAGIC;           /* magic mismatch */",
            f"    uint16_t hdr_maj = (hdr->version >> 8U) & 0xFFU;",
            f"    uint16_t local_maj = ({pname}_VERSION >> 8U) & 0xFFU;",
            f"    if (hdr_maj != local_maj)                                  return {pname}_HDR_ERR_VERSION;         /* major version mismatch */",
            f"    if (hdr->payload_len > {pname}_MAX_PAYLOAD)               return {pname}_HDR_ERR_PAYLOAD_TOO_BIG; /* payload overflow */",
            f"    if (hdr->payload_len != (uint16_t)payload_len)            return {pname}_HDR_ERR_LEN_MISMATCH;    /* size mismatch */",
            f"    uint32_t expected_crc = {n}_frame_crc(hdr, payload, payload_len);",
            f"    if (hdr->crc32 != expected_crc)                           return {pname}_HDR_ERR_CRC;             /* CRC mismatch */",
            "",
            "    /* Opcode check */",
            "    bool opcode_valid = false;",
            "    switch (hdr->opcode) {",
            *(f"        case {m.name}: opcode_valid = true; break;" for m in p.messages),
            "        default: break;",
            "    }",
            f"    if (!opcode_valid) return {pname}_HDR_ERR_OPCODE;                        /* unknown opcode */",
            "",
            "    /* Schema payload length check */",
            f"    uint16_t exp_len = {n}_expected_payload_len(hdr->opcode);",
            f"    if (exp_len != 0xFFFFU && hdr->payload_len != exp_len) {{",
            f"        return {pname}_HDR_ERR_LEN_SCHEMA;                                  /* schema payload length mismatch */",
            f"    }}",
            "",
            f"    return {pname}_HDR_OK;  /* OK */",
            "}",
            "",
            f"bool {n}_replay_check({n}_replay_state_t *st, uint32_t seq) {{",
            "    if (!st) return false;",
            "    if (!st->initialized) {{",
            "        st->last_seq = seq;",
            "        st->window = 1ULL;                            /* bit 0 = this seq seen */",
            "        st->initialized = true;",
            "        return true;",
            "    }}",
            "    int32_t delta = (int32_t)(seq - st->last_seq);   /* wrap-safe signed delta */",
            "    if (delta > 0) {{",
            "        /* Forward: slide the bitmap right by delta positions. */",
            f"        if ((uint32_t)delta >= {pname}_REPLAY_WINDOW)",
            "            st->window = 0ULL;                       /* old window shifted out entirely */",
            "        else",
            "            st->window <<= (uint32_t)delta;",
            "        st->window |= 1ULL;                          /* mark current seq (bit 0) seen */",
            "        st->last_seq = seq;",
            "        return true;",
            "    }}",
            "    if (delta == 0)",
            "        return false;                                /* exact repeat of highest seq */",
            "    uint32_t back = (uint32_t)(-delta);              /* how far behind the highest seq */",
            f"    if (back >= {pname}_REPLAY_WINDOW)",
            "        return false;                                /* older than the window */",
            "    uint64_t mask = 1ULL << back;",
            "    if (st->window & mask)",
            "        return false;                                /* already received => replay */",
            "    st->window |= mask;                              /* fresh, just out of order */",
            "    return true;",
            "}",
            "",
            self._replay_table_code(),
            "",
            self._auth_implementation(),
            "",
            "/* === Per-message payload wire serialization functions === */",
            self._payload_serialization_code(),
            "",
            self._opcode_map(),
        ]) + "\n"
