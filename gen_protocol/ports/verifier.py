"""
Port interface for Model Verifiers.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict


class ModelVerifier(ABC):
    """Abstract port interface for formal model verifiers."""

    @abstractmethod
    def verify(self, model_path: Path) -> Dict[str, Any]:
        pass
