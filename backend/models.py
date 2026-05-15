import json
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="owner")
    scheduled_scans = relationship("ScheduledScan", back_populates="owner")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target = Column(String, nullable=False)
    targets = Column(Text, nullable=True)           # JSON [{host, label}]
    ports = Column(String, nullable=True)           # preset key or custom spec
    scan_name = Column(String, nullable=True)
    modules = Column(Text, nullable=False)          # JSON list
    status = Column(String, default="pending")      # pending, running, completed, failed
    progress = Column(Text, default="{}")           # JSON progress per module
    results = Column(Text, default="{}")            # JSON results per module
    error_message = Column(Text, nullable=True)
    scheduled_scan_id = Column(Integer, ForeignKey("scheduled_scans.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    owner = relationship("User", back_populates="scans")
    scheduled_scan_ref = relationship("ScheduledScan", back_populates="runs", foreign_keys=[scheduled_scan_id])

    def get_modules(self):
        return json.loads(self.modules)

    def get_targets(self):
        if self.targets:
            data = json.loads(self.targets)
            result = []
            for t in data:
                if isinstance(t, dict):
                    result.append({"host": t.get("host", ""), "label": t.get("label")})
                else:
                    result.append({"host": str(t), "label": None})
            return result
        return [{"host": self.target, "label": None}]

    def get_progress(self):
        return json.loads(self.progress)

    def get_results(self):
        return json.loads(self.results)


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_name = Column(String, nullable=False)
    targets = Column(Text, nullable=False)          # JSON [{host, label}]
    modules = Column(Text, nullable=False)          # JSON list
    ports = Column(String, default="top1000")
    interval = Column(String, nullable=False)       # "1h", "6h", "12h", "daily", "3d", "weekly", "monthly"
    run_time = Column(String, default="00:00")      # "HH:MM" 24-hour
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)

    owner = relationship("User", back_populates="scheduled_scans")
    runs = relationship("Scan", back_populates="scheduled_scan_ref", foreign_keys="Scan.scheduled_scan_id")

    def get_targets(self):
        if self.targets:
            data = json.loads(self.targets)
            result = []
            for t in data:
                if isinstance(t, dict):
                    result.append({"host": t.get("host", ""), "label": t.get("label")})
                else:
                    result.append({"host": str(t), "label": None})
            return result
        return []

    def get_modules(self):
        return json.loads(self.modules) if self.modules else []
