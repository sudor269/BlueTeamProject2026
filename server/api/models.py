from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, BigInteger
from sqlalchemy.sql import func
from db import Base

class Host(Base):
    __tablename__ = "hosts"
    id = Column(Integer, primary_key=True)
    hostname = Column(String, unique=True, nullable=False)
    last_seen = Column(DateTime(timezone=True))
    status = Column(String, default="unknown")

class Policy(Base):
    __tablename__ = "policy"
    id = Column(Integer, primary_key=True, default=1)
    version = Column(Integer, nullable=False, default=1)
    audit_only = Column(Boolean, nullable=False, default=False)
    default_allow_if_no_serial = Column(Boolean, nullable=False, default=False)

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    hash_hex = Column(String(16), unique=True, nullable=False)
    serial_normalized = Column(Text)
    comment = Column(Text)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Event(Base):
    __tablename__ = "events"
    id = Column(BigInteger, primary_key=True)
    host = Column(Text)
    action = Column(Text, nullable=False)  
    reason = Column(Text)
    hash_hex = Column(String(16))
    serial_normalized = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())