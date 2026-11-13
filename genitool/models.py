"""Shared stage results; evidence is never a confirmed vulnerability."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StageResult:
    name: str
    status: str
    data: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

