from abc import ABC, abstractmethod
from typing import Any
from sentinel_scan.core.models import Host

class BaseModule(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    async def run(self, host: Host) -> Any:
        pass

class BasePlugin(BaseModule):
    def __init__(self, name: str, description: str):
        super().__init__(name, description)

    @abstractmethod
    async def check(self, host: Host) -> Any:
        pass
