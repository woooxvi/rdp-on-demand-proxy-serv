from __future__ import annotations

from abc import ABC, abstractmethod


class CloudProvider(ABC):
    @abstractmethod
    def get_instance_state(self) -> str:
        """Return normalized state: RUNNING / STOPPED / PENDING / UNKNOWN."""

    @abstractmethod
    def start_instance(self) -> None:
        pass

    @abstractmethod
    def stop_instance(self, stop_mode: str) -> None:
        pass
