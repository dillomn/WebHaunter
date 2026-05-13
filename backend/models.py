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


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target = Column(String, nullable=False)
    scan_name = Column(String, nullable=True)
    modules = Column(Text, nullable=False)  # JSON list
    status = Column(String, default="pending")  # pending, running, completed, failed
    progress = Column(Text, default="{}")  # JSON progress per module
    results = Column(Text, default="{}")  # JSON results per module
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    owner = relationship("User", back_populates="scans")

    def get_modules(self):
        return json.loads(self.modules)

    def get_progress(self):
        return json.loads(self.progress)

    def get_results(self):
        return json.loads(self.results)
