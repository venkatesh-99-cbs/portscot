from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class Service(BaseModel):
    port: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    banner: Optional[str] = None
    tls_info: Optional[Dict[str, Any]] = None

class Host(BaseModel):
    address: str
    hostname: Optional[str] = None
    status: str = "unknown"
    os_name: Optional[str] = None
    os_accuracy: Optional[int] = None
    services: List[Service] = []
    findings: List['Finding'] = []
    last_seen: datetime = Field(default_factory=datetime.now)

class Finding(BaseModel):
    title: str
    description: str
    severity: str  # info, low, medium, high, critical
    remediation: Optional[str] = None
    plugin_name: str

class ScanResult(BaseModel):
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    hosts: List[Host] = []
    summary: Dict[str, Any] = {}
    findings: List[Finding] = []
