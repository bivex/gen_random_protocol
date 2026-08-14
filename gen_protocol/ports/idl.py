"""
Port interface for Specification Loaders and Exporters.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from gen_protocol.domain.models import Protocol


class SpecLoader(ABC):
    """Abstract port interface for loading Protocol from spec file."""

    @abstractmethod
    def load(self, path: Path, *, seed: Optional[str] = None) -> Protocol:
        pass


class SpecExporter(ABC):
    """Abstract port interface for exporting Protocol to spec format."""

    @abstractmethod
    def export(self, proto: Protocol) -> str:
        pass
