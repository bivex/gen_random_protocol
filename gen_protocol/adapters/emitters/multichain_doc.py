"""
Adapter emitting MultiChain Markdown RFC specification (MULTICHAIN_SPEC.md).
"""

from datetime import datetime, timezone
from gen_protocol.domain.models import MultiChainSuite


class MultiChainMarkdownEmitter:
    def __init__(self, suite: MultiChainSuite) -> None:
        self.suite = suite

    def emit(self) -> str:
        s = self.suite
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            f"# {s.name} MultiChain Protocol Suite Specification",
            f"",
            f"**Chain Link Count:** `{len(s.protocols)}` interconnected protocols  ",
            f"**Generated:** `{ts}`  ",
            f"**Seed:** `{s.seed}`",
            f"",
            f"---",
            f"",
            f"## 1. MultiChain Network Architecture",
            f"",
            f"This multichain protocol suite defines `{len(s.protocols)}` interconnected, cryptographically seeded protocol links.",
            f"Cross-chain tunneling is established via dedicated encapsulated bridge frames.",
            f"",
            f"```text",
        ]

        diagram_links = " ---> ".join(f"[{p.name}]" for p in s.protocols)
        lines.append(f"  {diagram_links}")
        lines += [
            f"```",
            f"",
            f"## 2. Chain Protocol Directory",
            f"",
            f"| Link Index | Protocol Name | Pattern | Endianness | Magic Constant | Messages | Max Payload |",
            f"|---|---|---|---|---|---|---|",
        ]

        for i, p in enumerate(s.protocols):
            lines.append(
                f"| Link `{i+1}` | `{p.name}` | `{p.pattern.upper()}` | `{p.endian}` | `0x{p.magic:08X}` | `{len(p.messages)}` | `{p.max_payload_size} B` |"
            )

        lines += [
            f"",
            f"## 3. Cross-Chain Bridges & Tunnels",
            f"",
            f"| Bridge Index | Source Protocol | Target Protocol | Tunnel Opcode | Encapsulated Payload Size |",
            f"|---|---|---|---|---|",
        ]

        for i, (src, dst) in enumerate(s.bridges):
            src_proto = next(p for p in s.protocols if p.name == src)
            bridge_msg = next(m for m in src_proto.messages if f"BRIDGE_TO_{dst}" in m.name)
            lines.append(
                f"| Bridge `{i+1}` | `{src}` | `{dst}` | `0x{bridge_msg.opcode:04X}` | `128 B` |"
            )

        lines += [
            f"",
            f"## 4. Individual Protocol Specifications",
            f"",
            f"Detailed specifications for each protocol link are available in their respective directories:",
        ]
        for p in s.protocols:
            lines.append(f"- [`{p.name}` Spec](./{p.name.lower()}/PROTOCOL_SPEC.md)")

        return "\n".join(lines) + "\n"
