"""
Domain Entity and Value Object Models.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class Field:
    name: str
    ctype: str
    bits: Optional[int] = None        # None = scalar, int = bitfield width
    array_size: Optional[int] = None  # None = scalar, int = fixed array size
    comment: str = ""


@dataclass
class Message:
    name: str
    opcode: int                       # 16-bit wire opcode (0x0001 - 0xFFFE; random generator samples 0x0001 - 0x00FE)
    fields: List[Field]
    direction: str                    # "C->S" | "S->C" | "BIDI"
    description: str


@dataclass
class Enum:
    name: str
    members: List[Tuple[str, int]]    # (name, value)


@dataclass
class Protocol:
    name: str
    version_major: int
    version_minor: int
    version_patch: int
    magic: int                        # 32-bit integer magic constant
    pattern: str
    seed: str
    messages: List[Message]
    enums: List[Enum]
    header_struct_name: str
    max_payload_size: int
    endian: str                       # "little" | "big"
    description: str
    auth: Optional[str] = None        # None | "hmac-sha256"


@dataclass
class MultiChainSuite:
    name: str
    seed: str
    protocols: List[Protocol]
    bridges: List[Tuple[str, str]]    # (from_proto, to_proto)

