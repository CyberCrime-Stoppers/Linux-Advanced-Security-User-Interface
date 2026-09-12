from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field
import uuid


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    check: str                    # e.g. "setuid_scan"
    host: str = "localhost"
    severity: Severity
    title: str
    detail: str = ""
    path: str | None = None
    remediation: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
