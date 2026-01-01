"""Data models for persistence."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
import json


@dataclass
class Target:
    """Scan target."""
    id: Optional[int] = None
    value: str = ""
    target_type: str = ""  # domain, ip, url
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "value": self.value, "target_type": self.target_type,
            "created_at": self.created_at.isoformat(), "metadata": self.metadata
        }


@dataclass
class Finding:
    """Vulnerability or discovery finding."""
    id: Optional[int] = None
    scan_id: Optional[int] = None
    finding_type: str = ""  # vuln, port, subdomain, file, etc.
    severity: str = "info"  # critical, high, medium, low, info
    title: str = ""
    description: str = ""
    evidence: str = ""
    url: str = ""
    param: str = ""
    payload: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "scan_id": self.scan_id, "finding_type": self.finding_type,
            "severity": self.severity, "title": self.title, "description": self.description,
            "evidence": self.evidence, "url": self.url, "param": self.param,
            "payload": self.payload, "raw_data": self.raw_data,
            "created_at": self.created_at.isoformat()
        }


@dataclass
class Scan:
    """Scan session."""
    id: Optional[int] = None
    target_id: Optional[int] = None
    scan_type: str = ""  # full, port, vuln, recon, etc.
    status: str = "pending"  # pending, running, completed, failed
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    config: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "id": self.id, "target_id": self.target_id, "scan_type": self.scan_type,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "config": self.config, "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings]
        }
