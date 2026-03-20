from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from backend.database.database import Base


class Role(Base):

    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)


class User(Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password_hash = Column(String)
    role_id = Column(Integer, ForeignKey("roles.id"))
    created_at = Column(DateTime, default=func.now())

    role = relationship("Role")


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

from sqlalchemy import Column, Integer, String, JSON
from .database import Base

class User(Base):
    __tablename__ = "users"
    # This line prevents the 'InvalidRequestError' you saw in your screenshot
    __table_args__ = {'extend_existing': True} 

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    # "root" for admin, "user" for standard users
    role = Column(String, default="user") 
    
    # List of allowed services: ["file_scan", "link_scan", "github_scan"]
    permissions = Column(JSON, default=["link_scan"])