from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ChatMessage:
    role: str  # "user" or "assistant"
    content: str


class TargetAdapter(ABC):
    @abstractmethod
    async def send_turn(self, history: list[ChatMessage], user_turn: str) -> str:
        """Send a new user turn and return the assistant's response text."""
        ...

    async def close(self) -> None:
        return None
