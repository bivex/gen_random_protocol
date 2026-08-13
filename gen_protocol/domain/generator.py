"""
Protocol Generator Domain Service.
"""

from random import Random
from typing import List, Optional, Set

from gen_protocol.domain.models import Enum, Field, Message, MultiChainSuite, Protocol
from gen_protocol.domain.rules import calculate_magic, msg_wire_size, sanitize_proto_name
from gen_protocol.domain.types import (
    C_TYPE_KEYS, C_TYPE_WEIGHTS, C_TYPES, FIELD_ADJECTIVES,
    MSG_VERBS, PATTERNS, PROTO_NOUNS, PROTO_SUFFIXES
)


class ProtocolGenerator:
    """Domain service for producing randomized Protocol entities."""

    def __init__(self, rng: Random, seed: str) -> None:
        self.rng = rng
        self.seed = seed

    def _pick(self, seq):
        return self.rng.choice(seq)

    def _weighted_pick(self, seq, weights):
        return self.rng.choices(seq, weights=weights, k=1)[0]

    def _unique_name(self, base: str, used: Set[str]) -> str:
        name = base
        suffix = 0
        while name in used:
            suffix += 1
            name = f"{base}_{suffix}"
        used.add(name)
        return name

    def _free_opcode(self, proto: Protocol, prefer: tuple = ()) -> int:
        """Return an opcode in 0x01..0xFE not yet used by proto.

        Tries the preferred values first, then scans the full valid range.
        Used for injected messages (e.g. cross-chain bridges) that must not
        collide with randomly assigned message opcodes.
        """
        used = {m.opcode for m in proto.messages}
        for op in prefer:
            if op not in used:
                return op
        for op in range(0x01, 0x00FF):  # 0x01..0xFE inclusive
            if op not in used:
                return op
        raise ValueError(f"{proto.name}: no free opcode available for injected message")

    def proto_name(self, forced: Optional[str]) -> str:
        if forced:
            clean = sanitize_proto_name(forced)
            if clean != forced.upper().replace(' ', '_'):
                print(f"[gen_protocol]  name sanitized: {forced!r} → {clean!r}")
            return clean
        noun = self._pick(PROTO_NOUNS)
        suffix = self._pick(PROTO_SUFFIXES)
        return f"{noun}_{suffix}"

    def _gen_field(self, used_names: Set[str],
                   allow_array: bool = True,
                   allow_bitfield: bool = True) -> Field:
        adj = self._pick(FIELD_ADJECTIVES)
        name = self._unique_name(adj, used_names)
        tkey = self._weighted_pick(C_TYPE_KEYS, C_TYPE_WEIGHTS)
        ctype, _ = C_TYPES[tkey]

        bits = None
        array_size = None

        if allow_bitfield and tkey.startswith("u") and self.rng.random() < 0.18:
            bits = self.rng.choice([1, 2, 3, 4])
        elif allow_array and self.rng.random() < 0.22:
            array_size = self.rng.choice([4, 8, 16, 32, 64, 128, 256])

        comment = f"Protocol {name} field carry ({tkey})"
        return Field(name=name, ctype=ctype, bits=bits,
                     array_size=array_size, comment=comment)

    def _gen_fields(self, n: int) -> List[Field]:
        used: Set[str] = set()
        return [self._gen_field(used) for _ in range(n)]

    def _gen_enum(self, proto_name: str, tag: str, member_names: List[str]) -> Enum:
        enum_name = f"{proto_name}_{tag}_t"
        seen: Set[str] = set()
        vals: List[tuple[str, int]] = []
        counter = 0
        for m in member_names:
            key = f"{proto_name}_{tag}_{m}"
            if key in seen:
                continue
            seen.add(key)
            vals.append((key, counter))
            counter += 1
        return Enum(name=enum_name, members=vals)

    def _gen_message(self, proto_name: str,
                     used_ops: Set[int], used_names: Set[str],
                     max_fields: int, pattern: str) -> Message:
        if len(used_ops) >= 254:
            raise ValueError("Cannot generate more than 254 unique opcodes per protocol")

        op = self.rng.randint(0x01, 0xFE)
        while op in used_ops:
            op = self.rng.randint(0x01, 0xFE)
        used_ops.add(op)

        verb = self._pick(MSG_VERBS)
        name = self._unique_name(f"{proto_name}_MSG_{verb}", used_names)

        injected_count = 2 if pattern in ("rpc", "stream") else (1 if pattern in ("reqrsp", "pubsub", "fsm") else 0)
        n_random = max(0, max_fields - injected_count)
        fields = self._gen_fields(n_random) if n_random > 0 else []

        if pattern == "reqrsp":
            direction = "C->S" if ("REQUEST" in verb or "QUERY" in verb or "FETCH" in verb) else ("S->C" if "RESPONSE" in verb or "ACK" in verb else self._pick(["C->S", "S->C", "BIDI"]))
            fields.insert(0, Field(name="request_id", ctype="uint32_t", comment="Correlation ID matching request to response"))
        elif pattern == "pubsub":
            direction = "C->S" if ("SUBSCRIBE" in verb or "REGISTER" in verb) else ("S->C" if "PUBLISH" in verb or "NOTIFY" in verb else self._pick(["C->S", "S->C", "BIDI"]))
            fields.insert(0, Field(name="topic_id", ctype="uint32_t", comment="PubSub channel or topic identifier"))
        elif pattern == "rpc":
            direction = "C->S" if ("CALL" in verb or "REQUEST" in verb or "INVOKE" in verb) else ("S->C" if "RETURN" in verb or "RESPONSE" in verb else self._pick(["C->S", "S->C", "BIDI"]))
            fields.insert(0, Field(name="method_id", ctype="uint16_t", comment="RPC procedure method index"))
            fields.insert(1, Field(name="call_id", ctype="uint32_t", comment="RPC invocation sequence ID"))
        elif pattern == "stream":
            direction = "C->S" if "PUSH" in verb or "TRANSFER" in verb else self._pick(["C->S", "S->C", "BIDI"])
            fields.insert(0, Field(name="stream_id", ctype="uint32_t", comment="Stream multiplexing identifier"))
            fields.insert(1, Field(name="chunk_offset", ctype="uint64_t", comment="Byte offset within stream"))
        elif pattern == "fsm":
            direction = self._pick(["C->S", "S->C", "BIDI"])
            fields.insert(0, Field(name="state_id", ctype="uint8_t", comment="Current state machine phase ID"))
        else:
            direction = self._pick(["C->S", "S->C", "BIDI"])

        if len(fields) > max_fields:
            fields = fields[:max_fields]

        desc_tmpl = [
            f"Initiates a {verb.lower()} transaction",
            f"Signals {verb.lower()} event to peer",
            f"Carries {verb.lower()} payload",
            f"Requests {verb.lower()} acknowledgement",
            f"Conveys {verb.lower()} state change",
        ]
        desc = self._pick(desc_tmpl)
        return Message(name=name, opcode=op, fields=fields, direction=direction, description=desc)

    def generate(self, *,
                 name_hint: Optional[str] = None,
                 n_messages: Optional[int] = None,
                 max_fields: Optional[int] = None,
                 pattern: str = "auto") -> Protocol:

        if pattern == "auto":
            pattern = self._pick(PATTERNS)

        name = self.proto_name(name_hint)
        v_maj = self.rng.randint(1, 5)
        v_min = self.rng.randint(0, 15)
        v_pat = self.rng.randint(0, 99)
        magic = calculate_magic(name, self.seed)
        endian = self._pick(["little", "big"])

        n_msg = n_messages if n_messages is not None else self.rng.randint(4, 16)
        m_fld = max_fields if max_fields is not None else self.rng.randint(3, 10)

        used_ops: Set[int] = set()
        used_names: Set[str] = set()
        messages: List[Message] = []

        for _ in range(n_msg):
            msg = self._gen_message(name, used_ops, used_names, m_fld, pattern)
            messages.append(msg)

        enums: List[Enum] = [
            self._gen_enum(name, "DIRECTION", ["CLIENT_TO_SERVER", "SERVER_TO_CLIENT", "BROADCAST", "MULTICAST", "LOOPBACK"]),
            self._gen_enum(name, "ERR", ["OK", "TIMEOUT", "INVALID_OPCODE", "AUTH_FAIL", "PAYLOAD_TOO_LARGE", "CHECKSUM_MISMATCH", "UNSUPPORTED_VERSION", "RESOURCE_EXHAUSTED", "PROTOCOL_VIOLATION", "INTERNAL_ERROR"]),
            self._gen_enum(name, "STATE", ["INIT", "READY", "BUSY", "DONE", "FAILED"]),
        ]

        max_pay = max((msg_wire_size(m) for m in messages), default=0)
        # Pad to multiple of 4 or minimum size
        max_pay = max(1024, ((max_pay + 3) // 4) * 4)

        desc_map = {
            "reqrsp": "Request-Response correlated framing protocol",
            "stream": "Streaming multiplexed binary frame protocol",
            "pubsub": "Publish-Subscribe topic-based binary protocol",
            "rpc":    "Remote Procedure Call protocol — typed method invocation",
            "fsm":    "Finite State Machine controlled session protocol",
        }

        return Protocol(
            name=name,
            version_major=v_maj,
            version_minor=v_min,
            version_patch=v_pat,
            magic=magic,
            pattern=pattern,
            seed=self.seed,
            messages=messages,
            enums=enums,
            header_struct_name=f"{name.lower()}_hdr_t",
            max_payload_size=max_pay,
            endian=endian,
            description=desc_map.get(pattern, "Custom binary protocol"),
        )

    def generate_multichain(self, count: int, *,
                            name_prefix: Optional[str] = None,
                            n_messages: Optional[int] = None,
                            max_fields: Optional[int] = None,
                            pattern: str = "auto") -> MultiChainSuite:
        if count < 1 or count > 32:
            raise ValueError("Multichain count must be between 1 and 32")

        base_name = name_prefix.upper() if name_prefix else f"CHAIN_{self.seed[:6].upper()}"
        protocols: List[Protocol] = []
        bridges: List[tuple[str, str]] = []

        for i in range(count):
            sub_name = f"{base_name}_LINK_{i+1}"
            proto = self.generate(
                name_hint=sub_name,
                n_messages=n_messages,
                max_fields=max_fields,
                pattern=pattern
            )
            protocols.append(proto)

        # Inject cross-chain bridge messages between adjacent chain protocols
        for i in range(count - 1):
            src_p = protocols[i]
            dst_p = protocols[i + 1]
            bridges.append((src_p.name, dst_p.name))

            bridge_msg_name = f"{src_p.name}_MSG_BRIDGE_TO_{dst_p.name}"
            bridge_op = self._free_opcode(src_p, prefer=(0x00FE, 0x00FD, 0x00FC, 0x00FB))
            bridge_msg = Message(
                name=bridge_msg_name,
                opcode=bridge_op,
                fields=[
                    Field(name="target_magic", ctype="uint32_t", comment=f"Target chain magic constant (0x{dst_p.magic:08X})"),
                    Field(name="target_opcode", ctype="uint16_t", comment="Target chain message opcode"),
                    Field(name="tunnel_seq", ctype="uint32_t", comment="Cross-chain tunnel sequence counter"),
                    Field(name="tunnel_payload", ctype="uint8_t", array_size=128, comment="Encapsulated cross-chain payload"),
                ],
                direction="C->S",
                description=f"Tunnel bridge message encapsulating {dst_p.name} payload"
            )
            src_p.messages.append(bridge_msg)

        suite_name = f"MULTICHAIN_{base_name}"
        return MultiChainSuite(
            name=suite_name,
            seed=self.seed,
            protocols=protocols,
            bridges=bridges
        )

