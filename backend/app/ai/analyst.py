from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel


class Analyst(ABC):
    @property
    @abstractmethod
    def model_name(self) -> str: ...

    @property
    @abstractmethod
    def is_configured(self) -> bool: ...

    @abstractmethod
    def generate[T: BaseModel](
        self, system_instruction: str, payload: dict[str, Any], schema: type[T]
    ) -> T: ...