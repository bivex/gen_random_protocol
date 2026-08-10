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
