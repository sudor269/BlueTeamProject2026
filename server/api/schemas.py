from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class AgentHeartbeat(BaseModel):
    host: str
    ts: datetime
    status: str = "ok"

class AgentEventIn(BaseModel):
    host: str
    action: str
    reason: Optional[str] = None
    hash_hex: Optional[str] = None
    serial_normalized: Optional[str] = None

class PolicyOut(BaseModel):
    version: int
    audit_only: bool
    default_allow_if_no_serial: bool
    hashes: List[str]

class DeviceCreate(BaseModel):
    hash_hex: str = Field(min_length=16, max_length=16)
    serial_normalized: Optional[str] = None
    comment: Optional[str] = None

class PolicyUpdate(BaseModel):
    audit_only: bool
    default_allow_if_no_serial: bool