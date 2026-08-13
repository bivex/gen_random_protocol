"""
Domain Types and Constants.
"""

from typing import Dict, List, Tuple

_C_RESERVED = frozenset({
    'auto','break','case','char','const','continue','default','do',
    'double','else','enum','extern','float','for','goto','if','inline',
    'int','long','register','restrict','return','short','signed','sizeof',
    'static','struct','switch','typedef','union','unsigned','void',
    'volatile','while',
    '_bool','_complex','_imaginary','_alignas','_alignof','_atomic',
    '_generic','_noreturn','_static_assert','_thread_local',
    'bool','true','false','size_t','ptrdiff_t','intptr_t','uintptr_t',
})

PROTO_NOUNS = [
    "NEXUS", "FLUX", "VORTEX", "CIPHER", "AXIOM", "RELAY", "VECTOR", "CONDUIT",
    "HERALD", "STRATUM", "BEACON", "AETHER", "LATTICE", "PULSE", "CORONA", "APEX",
    "ZENITH", "PRISM", "QUORUM", "HELIOS", "SIGMA", "DELTA", "OMEGA", "ECHO",
    "TERRA", "SPECTRA", "RIFT", "NOVA", "LYNX", "COBALT", "TITAN", "FERRO",
    "QUASAR", "HYDRA", "PEGASUS", "ORCA", "ARGON", "NEON", "CHROME", "BASALT",
    "ASTRA", "SOLAR", "LUNAR", "POLAR", "NIMBUS", "KINETIC", "TEMPEST", "ORION",
    "VALKYRIE", "PHOENIX", "STARDUST", "NEBULA", "AURORA", "HALO", "RADIAN", "TENSOR",
]

PROTO_SUFFIXES = [
    "LINK", "NET", "BUS", "WIRE", "GATE", "CHAN", "SYNC", "FLOW", "HUB", "MUX",
    "CAST", "MESH", "EDGE", "NODE", "CORE", "SPAN", "PATH", "RACK", "PIPE", "SLOT",
    "GRID", "RING", "FABRIC", "BRIDGE", "TUNNEL", "PORTAL", "SOCKET", "VALVE", "PORT",
]

FIELD_ADJECTIVES = [
    "src", "dst", "seq", "ack", "flags", "status", "ctrl", "cfg", "data", "payload",
    "len", "checksum", "version", "type", "subtype", "group", "session", "stream",
    "priority", "ttl", "hop", "window", "offset", "tag", "id", "epoch", "nonce",
    "opcode", "reason", "code", "mask", "mode", "channel", "port", "addr",
    "timestamp", "signature", "key", "token", "reserved", "padding", "crc", "hash",
]

MSG_VERBS = [
    "CONNECT", "ACCEPT", "REJECT", "OPEN", "CLOSE", "PING", "PONG", "SYNC", "RESET",
    "SUBSCRIBE", "UNSUBSCRIBE", "PUBLISH", "REQUEST", "RESPONSE", "ACK", "NACK",
    "PUSH", "PULL", "FETCH", "COMMIT", "ROLLBACK", "HEARTBEAT", "HELLO", "BYE",
    "AUTH", "CHALLENGE", "GRANT", "REVOKE", "REGISTER", "DEREGISTER", "QUERY",
    "UPDATE", "DELETE", "INSERT", "NOTIFY", "ALERT", "ERROR", "STATUS", "METRICS",
    "FLOW_CTRL", "WINDOW_UPDATE", "KEEPALIVE", "PROBE", "DISCOVER", "ANNOUNCE",
    "HANDSHAKE", "NEGOTIATE", "CONFIGURE", "TRANSFER", "COMPLETE", "ABORT",
]

C_TYPES: Dict[str, Tuple[str, int]] = {
    "u8":   ("uint8_t",  1),
    "u16":  ("uint16_t", 2),
    "u32":  ("uint32_t", 4),
    "u64":  ("uint64_t", 8),
    "i8":   ("int8_t",   1),
    "i16":  ("int16_t",  2),
    "i32":  ("int32_t",  4),
    "i64":  ("int64_t",  8),
    "f32":  ("float",    4),
    "f64":  ("double",   8),
    "bool": ("uint8_t",  1),
}

C_TYPE_KEYS = list(C_TYPES.keys())
C_TYPE_WEIGHTS = [12, 10, 8, 4, 6, 5, 4, 2, 1, 1, 3]

PATTERNS = ["reqrsp", "stream", "pubsub", "rpc", "fsm"]

FIELD_SEMANTIC_RULES: Dict[str, Dict] = {
    # Lengths, sizes, offsets
    "len":       {"types": ("u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Payload length or size"},
    "length":    {"types": ("u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Payload length or size"},
    "size":      {"types": ("u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Data or element size"},
    "offset":    {"types": ("u16", "u32", "u64"), "allow_bitfield": False, "array": None, "comment": "Byte offset in stream or buffer"},

    # Crypto / Signatures / Hashes / Keys / Tokens
    "signature": {"types": ("u8",), "allow_bitfield": False, "array": (32, 64), "comment": "Cryptographic signature (Ed25519/HMAC)"},
    "sig":       {"types": ("u8",), "allow_bitfield": False, "array": (32, 64), "comment": "Short cryptographic signature"},
    "mac":       {"types": ("u8",), "allow_bitfield": False, "array": (16, 32), "comment": "Message Authentication Code"},
    "hash":      {"types": ("u8",), "allow_bitfield": False, "array": (16, 32, 64), "comment": "Digest or hash bytes"},
    "key":       {"types": ("u8",), "allow_bitfield": False, "array": (16, 32), "comment": "Cryptographic key material"},
    "token":     {"types": ("u8",), "allow_bitfield": False, "array": (16, 32), "comment": "Authentication token"},

    # Reserved / Padding
    "reserved":  {"types": ("u8", "u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Reserved for future use (must be zero)"},
    "padding":   {"types": ("u8", "u16"), "allow_bitfield": False, "array": None, "comment": "Padding bytes for struct alignment"},
    "pad":       {"types": ("u8", "u16"), "allow_bitfield": False, "array": None, "comment": "Padding bytes for struct alignment"},

    # Network Addresses / Host
    "addr":      {"types": ("u8", "u32"), "allow_bitfield": False, "array_if_u8": (4, 16), "comment": "Network address (IPv4/IPv6)"},
    "ip":        {"types": ("u8", "u32"), "allow_bitfield": False, "array_if_u8": (4, 16), "comment": "IP address"},
    "host":      {"types": ("u8", "u32"), "allow_bitfield": False, "array_if_u8": (4, 16), "comment": "Host address"},
    "src":       {"types": ("u8", "u32"), "allow_bitfield": False, "array_if_u8": (4, 16), "comment": "Source address (IPv4/IPv6)"},
    "dst":       {"types": ("u8", "u32"), "allow_bitfield": False, "array_if_u8": (4, 16), "comment": "Destination address (IPv4/IPv6)"},
    "port":      {"types": ("u16",), "allow_bitfield": False, "array": None, "comment": "Network port number"},

    # Timestamps / Epochs
    "timestamp": {"types": ("u64", "u32"), "allow_bitfield": False, "array": None, "comment": "Timestamp (milliseconds since epoch)"},
    "epoch":     {"types": ("u64", "u32"), "allow_bitfield": False, "array": None, "comment": "Epoch counter"},
    "time":      {"types": ("u64", "u32"), "allow_bitfield": False, "array": None, "comment": "System time value"},

    # Sequences / Nonces / IDs / Correlation
    "seq":       {"types": ("u16", "u32", "u64"), "allow_bitfield": False, "array": None, "comment": "Sequence number"},
    "sequence":  {"types": ("u16", "u32", "u64"), "allow_bitfield": False, "array": None, "comment": "Sequence counter"},
    "ack":       {"types": ("u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Acknowledgement sequence"},
    "window":    {"types": ("u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Flow-control window size"},
    "nonce":     {"types": ("u8", "u32", "u64"), "allow_bitfield": False, "array_if_u8": (8, 12, 16), "comment": "Anti-replay nonce"},
    "session":   {"types": ("u32", "u64"), "allow_bitfield": False, "array": None, "comment": "Session identifier"},
    "stream":    {"types": ("u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Stream channel ID"},
    "channel":   {"types": ("u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Logical channel identifier"},
    "id":        {"types": ("u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Entity identifier"},

    # Control / Flags / Status / Codes / Types
    "flags":     {"types": ("u8", "u16", "u32"), "allow_bitfield": True, "array": None, "comment": "Control flags bitmask"},
    "mask":      {"types": ("u8", "u16", "u32"), "allow_bitfield": True, "array": None, "comment": "Bitmask filter"},
    "mode":      {"types": ("u8", "u16"), "allow_bitfield": True, "array": None, "comment": "Operating mode flags"},
    "status":    {"types": ("u8", "u16"), "allow_bitfield": True, "array": None, "comment": "Status flags"},
    "ctrl":      {"types": ("u8", "u16", "u32"), "allow_bitfield": True, "array": None, "comment": "Control flags"},
    "cfg":       {"types": ("u8", "u16", "u32"), "allow_bitfield": True, "array": None, "comment": "Configuration flags"},
    "version":   {"types": ("u8", "u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Protocol or schema version"},
    "type":      {"types": ("u8", "u16"), "allow_bitfield": False, "array": None, "comment": "Subtype code"},
    "subtype":   {"types": ("u8", "u16"), "allow_bitfield": False, "array": None, "comment": "Secondary type code"},
    "code":      {"types": ("u8", "u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Status or error code"},
    "reason":    {"types": ("u8", "u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Reason code"},
    "opcode":    {"types": ("u8", "u16"), "allow_bitfield": False, "array": None, "comment": "Operation code"},
    "ttl":       {"types": ("u8", "u16"), "allow_bitfield": False, "array": None, "comment": "Time-to-live / hop limit"},
    "hop":       {"types": ("u8", "u16"), "allow_bitfield": False, "array": None, "comment": "Hop count"},
    "priority":  {"types": ("u8",), "allow_bitfield": True, "array": None, "comment": "Priority level"},
    "tag":       {"types": ("u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Tag identifier"},
    "group":     {"types": ("u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Group identifier"},

    # Data / Payload / Floating point metrics
    "data":      {"types": ("u8", "u16", "u32", "u64", "f32", "f64"), "allow_bitfield": False, "array_if_u8": (16, 32, 64, 128), "comment": "Data payload"},
    "payload":   {"types": ("u8", "u16", "u32", "u64"), "allow_bitfield": False, "array_if_u8": (16, 32, 64, 128, 256), "comment": "Message payload buffer"},
    "checksum":  {"types": ("u16", "u32"), "allow_bitfield": False, "array": None, "comment": "Checksum value"},
    "crc":       {"types": ("u16", "u32"), "allow_bitfield": False, "array": None, "comment": "CRC value"},
}

IDL_TO_C_TYPE = {
    "u8":   "uint8_t",
    "u16":  "uint16_t",
    "u32":  "uint32_t",
    "u64":  "uint64_t",
    "i8":   "int8_t",
    "i16":  "int16_t",
    "i32":  "int32_t",
    "i64":  "int64_t",
    "f32":  "float",
    "f64":  "double",
    "bool": "uint8_t",
}

C_TYPE_TO_IDL = {
    "uint8_t":  "u8",
    "uint16_t": "u16",
    "uint32_t": "u32",
    "uint64_t": "u64",
    "int8_t":   "i8",
    "int16_t":  "i16",
    "int32_t":  "i32",
    "int64_t":  "i64",
    "float":    "f32",
    "double":   "f64",
}

