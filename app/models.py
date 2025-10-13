"""
Database models for SecureDocs system.
Defines User, File, and AuditLog tables with relationships.
"""
from sqlalchemy import Column, Integer, String, ForeignKey, Enum, DateTime, LargeBinary, Text, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

Base = declarative_base()


class UserRole(enum.Enum):
    """User role enumeration for RBAC."""
    ADMIN = "Admin"
    MANAGER = "Manager"
    USER = "Standard User"


class User(Base):
    """User table with authentication and role information."""
    __tablename__ = 'users'
    
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.USER)
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    
    files = relationship("File", back_populates="owner")
    audit_logs = relationship("AuditLog", back_populates="user")
    
    def has_permission(self, action):
        """Check if user has permission for a specific action."""
        permissions = {
            UserRole.ADMIN: ["upload", "download", "rename", "delete", "view_logs", "manage_roles"],
            UserRole.MANAGER: ["upload", "download", "rename", "delete", "view_logs"],
            UserRole.USER: ["upload", "download"]
        }
        return action in permissions.get(self.role, [])


class File(Base):
    """File table with metadata and binary storage."""
    __tablename__ = 'files'
    
    file_id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(255), nullable=False)
    size = Column(Integer, nullable=False)
    owner_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    checksum = Column(String(64), nullable=False)
    file_data = Column(LargeBinary, nullable=True)
    is_deleted = Column(Integer, nullable=False, default=0)
    
    owner = relationship("User", back_populates="files")
    audit_logs = relationship("AuditLog", back_populates="file")


class AuditLog(Base):
    """Immutable audit log table for tracking all file operations."""
    __tablename__ = 'audit_logs'
    
    log_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id'), nullable=False)
    file_id = Column(Integer, ForeignKey('files.file_id'), nullable=True)
    action = Column(String(50), nullable=False)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    signature_hash = Column(String(64), nullable=False)
    
    user = relationship("User", back_populates="audit_logs")
    file = relationship("File", back_populates="audit_logs")
