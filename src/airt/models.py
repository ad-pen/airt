from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackClass(str, Enum):
    PROMPT_INJECTION = "prompt-injection"
    INDIRECT_INJECTION = "indirect-injection"
    JAILBREAK = "jailbreak"
    DATA_EXTRACTION = "data-extraction"
    POLICY_BYPASS = "policy-bypass"
    ROLE_CONFUSION = "role-confusion"
    AGENTIC_EXPLOITATION = "agentic-exploitation"
    RAG_POISONING = "rag-poisoning"


class Status(str, Enum):
    LIKELY_SUCCESS = "likely-success"
    FLAGS_PRESENT = "flags-present"
    DEFLECTED = "deflected"
    NO_SIGNAL = "no-signal"
    ERROR = "error"


class Flag(BaseModel):
    name: str
    evidence: str = ""
    turn_idx: int = 0


class SuccessCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contains_any: list[str] = Field(default_factory=list)
    contains_all: list[str] = Field(default_factory=list)
    regex_any: list[str] = Field(default_factory=list)
    min_length: int | None = None
    length_multiple_of_baseline: float | None = None


class Branch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    if_flag: str
    goto_turn: int


class PayloadTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user: str
    branches: list[Branch] = Field(default_factory=list)


class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    attack_class: AttackClass
    title: str
    description: str = ""
    severity_if_success: Severity = Severity.MEDIUM
    turns: list[PayloadTurn]
    success: SuccessCriteria = Field(default_factory=SuccessCriteria)
    partial: SuccessCriteria = Field(default_factory=SuccessCriteria)
    canary: str | None = None
    policy_keywords: list[str] = Field(default_factory=list)
    recommendation: str = ""
    owasp: str | None = None
    tags: list[str] = Field(default_factory=list)


class TargetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["POST", "GET", "PUT"] = "POST"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body_template: dict[str, Any] = Field(default_factory=dict)
    history_format: Literal["openai", "anthropic", "plain-latest"] = "openai"
    response_path: str = "choices.0.message.content"
    timeout_s: float = 60.0
    timeout: float = 30.0


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    request: TargetRequest


class TurnResult(BaseModel):
    idx: int
    user: str
    assistant: str
    flags: list[Flag] = Field(default_factory=list)
    status: Status = Status.NO_SIGNAL
    latency_ms: int = 0
    error: str | None = None


class SessionResult(BaseModel):
    id: str
    target_name: str
    payload_id: str
    payload_title: str
    attack_class: AttackClass
    started_at: datetime
    ended_at: datetime
    overall_status: Status
    turns: list[TurnResult]
    canary_used: str | None = None


class Finding(BaseModel):
    id: str
    session_id: str
    title: str
    severity: Severity
    attack_class: AttackClass
    notes: str = ""
    created_at: datetime


class JudgeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_base: str
    api_key: str = ""  # can come from env
    model: str
    temperature: float = 0.0


class DynamicConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_base: str
    api_key: str = ""
    model: str
    temperature: float = 0.7
    max_turns: int = 10


class ConfigError(Exception):
    """Raised for invalid target or payload configuration."""

    pass
