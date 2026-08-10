"""
Adapter emitting JSON manifest for MultiChain Suite (multichain_manifest.json).
"""

import json
from gen_protocol.adapters.emitters.json_manifest import protocol_to_dict
from gen_protocol.domain.models import MultiChainSuite


class MultiChainManifestEmitter:
    def __init__(self, suite: MultiChainSuite) -> None:
        self.suite = suite

    def emit(self) -> str:
        s = self.suite
        data = {
            "suite_name": s.name,
            "seed": s.seed,
            "chain_count": len(s.protocols),
            "bridges": [{"from": b[0], "to": b[1]} for b in s.bridges],
            "protocols": [protocol_to_dict(p) for p in s.protocols],
        }
        return json.dumps(data, indent=2) + "\n"
