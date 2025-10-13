"""
Storage abstraction layer for SecureDocs.
Provides pluggable interface for file storage with database implementation.
"""
import os
import hashlib
from abc import ABC, abstractmethod
from typing import BinaryIO, Optional
from sqlalchemy.orm import Session
from app.models import File


class StorageAdapter(ABC):
    """Abstract base class for storage adapters."""
    
    @abstractmethod
    def save_file(self, file_data: bytes, file_metadata: dict) -> dict:
        """Save file and return storage metadata."""
        pass
    
    @abstractmethod
    def retrieve_file(self, file_id: int) -> Optional[bytes]:
        """Retrieve file data by file_id."""
        pass
    
    @abstractmethod
    def delete_file(self, file_id: int) -> bool:
        """Delete file from storage."""
        pass
    
    @abstractmethod
    def update_file(self, file_id: int, file_data: bytes) -> bool:
        """Update existing file data."""
        pass


class DatabaseStorageAdapter(StorageAdapter):
    """Database storage adapter using BYTEA columns."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def save_file(self, file_data: bytes, file_metadata: dict) -> dict:
        """
        Save file data to database as BYTEA.
        Calculates checksum and stores metadata.
        """
        checksum = self._calculate_checksum(file_data)
        
        file_record = File(
            filename=file_metadata['filename'],
            size=len(file_data),
            owner_id=file_metadata['owner_id'],
            checksum=checksum,
            file_data=file_data,
            version=file_metadata.get('version', 1)
        )
        
        self.db.add(file_record)
        self.db.commit()
        self.db.refresh(file_record)
        
        return {
            'file_id': file_record.file_id,
            'filename': file_record.filename,
            'size': file_record.size,
            'checksum': file_record.checksum,
            'version': file_record.version,
            'created_at': file_record.created_at.isoformat()
        }
    
    def retrieve_file(self, file_id: int) -> Optional[bytes]:
        """Retrieve file data from database."""
        file_record = self.db.query(File).filter(
            File.file_id == file_id,
            File.is_deleted == 0
        ).first()
        
        if not file_record:
            return None
        
        return file_record.file_data
    
    def delete_file(self, file_id: int) -> bool:
        """
        Soft-delete file by marking is_deleted flag.
        Supports recoverability as per requirements.
        """
        file_record = self.db.query(File).filter(File.file_id == file_id).first()
        
        if not file_record:
            return False
        
        file_record.is_deleted = 1
        self.db.commit()
        return True
    
    def update_file(self, file_id: int, file_data: bytes) -> bool:
        """Update file data and increment version."""
        file_record = self.db.query(File).filter(
            File.file_id == file_id,
            File.is_deleted == 0
        ).first()
        
        if not file_record:
            return False
        
        file_record.file_data = file_data
        file_record.size = len(file_data)
        file_record.checksum = self._calculate_checksum(file_data)
        file_record.version += 1
        
        self.db.commit()
        return True
    
    def _calculate_checksum(self, file_data: bytes) -> str:
        """Calculate SHA-256 checksum of file data."""
        return hashlib.sha256(file_data).hexdigest()


class FilesystemStorageAdapter(StorageAdapter):
    """
    Filesystem storage adapter for future implementation.
    Stores files in local filesystem with metadata in database.
    """
    
    def __init__(self, db: Session, storage_path: str):
        self.db = db
        self.storage_path = storage_path
        os.makedirs(storage_path, exist_ok=True)
    
    def save_file(self, file_data: bytes, file_metadata: dict) -> dict:
        """Save file to filesystem and metadata to database."""
        raise NotImplementedError("Filesystem storage not yet implemented")
    
    def retrieve_file(self, file_id: int) -> Optional[bytes]:
        """Retrieve file from filesystem."""
        raise NotImplementedError("Filesystem storage not yet implemented")
    
    def delete_file(self, file_id: int) -> bool:
        """Delete file from filesystem."""
        raise NotImplementedError("Filesystem storage not yet implemented")
    
    def update_file(self, file_id: int, file_data: bytes) -> bool:
        """Update file in filesystem."""
        raise NotImplementedError("Filesystem storage not yet implemented")


class S3StorageAdapter(StorageAdapter):
    """
    AWS S3 storage adapter for future implementation.
    Stores files in S3 bucket with metadata in database.
    """
    
    def __init__(self, db: Session, bucket_name: str):
        self.db = db
        self.bucket_name = bucket_name
    
    def save_file(self, file_data: bytes, file_metadata: dict) -> dict:
        """Save file to S3 bucket."""
        raise NotImplementedError("S3 storage not yet implemented")
    
    def retrieve_file(self, file_id: int) -> Optional[bytes]:
        """Retrieve file from S3."""
        raise NotImplementedError("S3 storage not yet implemented")
    
    def delete_file(self, file_id: int) -> bool:
        """Delete file from S3."""
        raise NotImplementedError("S3 storage not yet implemented")
    
    def update_file(self, file_id: int, file_data: bytes) -> bool:
        """Update file in S3."""
        raise NotImplementedError("S3 storage not yet implemented")


def get_storage_adapter(db: Session) -> StorageAdapter:
    """
    Factory function to get appropriate storage adapter.
    Based on STORAGE_MODE environment variable.
    """
    storage_mode = os.getenv("STORAGE_MODE", "database")
    
    if storage_mode == "database":
        return DatabaseStorageAdapter(db)
    elif storage_mode == "filesystem":
        storage_path = os.getenv("STORAGE_PATH", "./file_storage")
        return FilesystemStorageAdapter(db, storage_path)
    elif storage_mode == "s3":
        bucket_name = os.getenv("S3_BUCKET_NAME", "securedocs-bucket")
        return S3StorageAdapter(db, bucket_name)
    else:
        raise ValueError(f"Unknown storage mode: {storage_mode}")
