"""
Port interface for Code and Artifact Emitters.
"""

from abc import ABC, abstractmethod
from gen_protocol.domain.models import Protocol


class CodeEmitter(ABC):
    """Abstract port interface for code and spec emitters."""

    def __init__(self, proto: Protocol) -> None:
        self.p = proto

    @abstractmethod
    def emit(self) -> str:
        """Produce formatted string artifact representation of protocol."""
        pass
