from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from backend.database.database import Base

# --- ROLE MANAGEMENT ---
class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)

# --- USER MANAGEMENT (MERGED & CLEANED) ---
class User(Base):
    __tablename__ = "users"
    # extend_existing allows us to redefine the class if it was partially loaded
    __table_args__ = {'extend_existing': True} 

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    
    # Using password_hash to maintain compatibility with your login logic
    password_hash = Column(String) 
    hashed_password = Column(String) 
    
    # "root" for admin, "user" for standard users
    role = Column(String, default="user") 
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=True)
    
    # List of allowed services: ["file_scan", "link_scan", "github_scan"]
    permissions = Column(JSON, default=["file_scan", "link_scan"])
    created_at = Column(DateTime, default=func.now())

    # Relationships
    user_role = relationship("Role")
    scans = relationship("ScanHistory", back_populates="owner")

# --- SCAN HISTORY (THE MISSING CLASS) ---
class ScanHistory(Base):
    __tablename__ = "scan_history"
    
    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String, unique=True, index=True) # Celery Task ID
    filename = Column(String)
    risk_score = Column(Float)
    vulnerabilities = Column(Integer)
    status = Column(String, default="completed")
    timestamp = Column(DateTime, default=func.now())
    
    # Foreign Key to connect scan to the specific user
    user_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="scans")

# --- API & WORKER INFRASTRUCTURE ---
class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=func.now())

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id = Column(Integer, primary_key=True)
    input_name = Column(String)
    input_type = Column(String)
    detected_language = Column(String)
    tests_performed = Column(Text)
    status = Column(String)
    created_at = Column(DateTime, default=func.now())

class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"))
    result = Column(Text)
    error_logs = Column(Text)
    ai_remediation = Column(Text)
    cvss_score = Column(String)

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    job_id = Column(String)
    path = Column(String)
    created_at = Column(DateTime, default=func.now())

class WorkerNode(Base):
    __tablename__ = "worker_nodes"
    id = Column(Integer, primary_key=True)
    hostname = Column(String)
    status = Column(String)
    last_heartbeat = Column(DateTime)