"""
Main FastAPI application for SecureDocs.
Provides REST API endpoints for authentication and file management.
"""
import os
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File as FastAPIFile, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import BaseModel
from io import BytesIO

from app.models import User, File, UserRole
from app.auth import (
    register_user, authenticate_user, create_access_token, 
    create_refresh_token, get_current_user, require_permission, get_client_ip
)
from app.storage import get_storage_adapter
from app.audit import log_action, get_audit_logs, export_audit_logs_json, export_audit_logs_csv, get_audit_statistics
from app.utils import get_db, init_database, sanitize_filename, validate_file_size


app = FastAPI(title="SecureDocs API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Initialize database on application startup."""
    init_database()


class RegisterRequest(BaseModel):
    username: str
    password: str
    role: Optional[str] = "User"


class LoginRequest(BaseModel):
    username: str
    password: str


class RenameRequest(BaseModel):
    new_filename: str


@app.post("/api/register")
async def register(request: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new user with hashed password."""
    try:
        role_mapping = {
            "Admin": UserRole.ADMIN,
            "Manager": UserRole.MANAGER,
            "User": UserRole.USER
        }
        role = role_mapping.get(request.role, UserRole.USER)
        
        user = register_user(db, request.username, request.password, role)
        return {
            "status": "success",
            "message": "User registered successfully",
            "user": {
                "user_id": user.user_id,
                "username": user.username,
                "role": user.role.value
            }
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/login")
async def login(request: LoginRequest, req: Request, db: Session = Depends(get_db)):
    """Authenticate user and issue JWT tokens."""
    user = authenticate_user(db, request.username, request.password)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(user.user_id, user.username, user.role)
    refresh_token = create_refresh_token(user.user_id)
    
    ip_address = get_client_ip(req)
    log_action(db, user.user_id, "LOGIN", None, ip_address)
    
    return {
        "status": "success",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.value
        }
    }


@app.post("/api/upload")
async def upload_file(
    file: UploadFile = FastAPIFile(...),
    req: Request = None,
    user: User = Depends(require_permission("upload")),
    db: Session = Depends(get_db)
):
    """
    Upload a file securely with permission validation.
    Stores file data and logs the action.
    """
    file_data = await file.read()
    
    if not validate_file_size(len(file_data)):
        raise HTTPException(status_code=413, detail="File too large")
    
    filename = sanitize_filename(file.filename)
    
    storage = get_storage_adapter(db)
    metadata = storage.save_file(file_data, {
        'filename': filename,
        'owner_id': user.user_id
    })
    
    ip_address = get_client_ip(req)
    log_action(db, user.user_id, "UPLOAD", metadata['file_id'], ip_address)
    
    return {
        "status": "success",
        "file": metadata
    }


@app.get("/api/files")
async def list_files(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all files accessible to the current user."""
    if user.role == UserRole.ADMIN or user.role == UserRole.MANAGER:
        files = db.query(File).filter(File.is_deleted == 0).all()
    else:
        files = db.query(File).filter(
            File.owner_id == user.user_id,
            File.is_deleted == 0
        ).all()
    
    file_list = []
    for f in files:
        file_list.append({
            'file_id': f.file_id,
            'filename': f.filename,
            'size': f.size,
            'owner_id': f.owner_id,
            'version': f.version,
            'created_at': f.created_at.isoformat(),
            'checksum': f.checksum
        })
    
    return {
        "status": "success",
        "files": file_list
    }


@app.get("/api/download/{file_id}")
async def download_file(
    file_id: int,
    req: Request,
    user: User = Depends(require_permission("download")),
    db: Session = Depends(get_db)
):
    """
    Download a file with access control validation.
    Streams file data to client.
    """
    file_record = db.query(File).filter(
        File.file_id == file_id,
        File.is_deleted == 0
    ).first()
    
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    
    if user.role not in [UserRole.ADMIN, UserRole.MANAGER]:
        if file_record.owner_id != user.user_id:
            raise HTTPException(status_code=403, detail="Access denied")
    
    storage = get_storage_adapter(db)
    file_data = storage.retrieve_file(file_id)
    
    if not file_data:
        raise HTTPException(status_code=404, detail="File data not found")
    
    ip_address = get_client_ip(req)
    log_action(db, user.user_id, "DOWNLOAD", file_id, ip_address)
    
    return StreamingResponse(
        BytesIO(file_data),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={file_record.filename}"}
    )


@app.put("/api/files/{file_id}/rename")
async def rename_file(
    file_id: int,
    request: RenameRequest,
    req: Request,
    user: User = Depends(require_permission("rename")),
    db: Session = Depends(get_db)
):
    """Rename file metadata (owner or Admin/Manager only)."""
    file_record = db.query(File).filter(
        File.file_id == file_id,
        File.is_deleted == 0
    ).first()
    
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    
    if user.role not in [UserRole.ADMIN, UserRole.MANAGER]:
        if file_record.owner_id != user.user_id:
            raise HTTPException(status_code=403, detail="Access denied")
    
    new_filename = sanitize_filename(request.new_filename)
    file_record.filename = new_filename
    db.commit()
    
    ip_address = get_client_ip(req)
    log_action(db, user.user_id, "RENAME", file_id, ip_address)
    
    return {
        "status": "success",
        "message": "File renamed successfully",
        "filename": new_filename
    }


@app.delete("/api/files/{file_id}")
async def delete_file(
    file_id: int,
    req: Request,
    user: User = Depends(require_permission("delete")),
    db: Session = Depends(get_db)
):
    """
    Soft-delete a file (owner or Admin/Manager only).
    Supports recoverability as per requirements.
    """
    file_record = db.query(File).filter(
        File.file_id == file_id,
        File.is_deleted == 0
    ).first()
    
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    
    if user.role not in [UserRole.ADMIN, UserRole.MANAGER]:
        if file_record.owner_id != user.user_id:
            raise HTTPException(status_code=403, detail="Access denied")
    
    storage = get_storage_adapter(db)
    storage.delete_file(file_id)
    
    ip_address = get_client_ip(req)
    log_action(db, user.user_id, "DELETE", file_id, ip_address)
    
    return {
        "status": "success",
        "message": "File deleted successfully"
    }


@app.get("/api/audit/logs")
async def get_logs(
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    user: User = Depends(require_permission("view_logs")),
    db: Session = Depends(get_db)
):
    """Retrieve audit logs (Admin/Manager only)."""
    logs = get_audit_logs(db, user_id=user_id, action=action, limit=limit, offset=offset)
    return {
        "status": "success",
        "logs": logs,
        "total": len(logs)
    }


@app.get("/api/audit/export/json")
async def export_logs_json(
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    user: User = Depends(require_permission("view_logs")),
    db: Session = Depends(get_db)
):
    """Export audit logs as signed JSON snapshot."""
    json_data = export_audit_logs_json(db, user_id=user_id, action=action)
    return Response(
        content=json_data,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=audit_logs.json"}
    )


@app.get("/api/audit/export/csv")
async def export_logs_csv(
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    user: User = Depends(require_permission("view_logs")),
    db: Session = Depends(get_db)
):
    """Export audit logs as CSV format."""
    csv_data = export_audit_logs_csv(db, user_id=user_id, action=action)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_logs.csv"}
    )


@app.get("/api/audit/statistics")
async def get_statistics(
    user: User = Depends(require_permission("view_logs")),
    db: Session = Depends(get_db)
):
    """Get audit statistics for dashboard."""
    stats = get_audit_statistics(db)
    return {
        "status": "success",
        "statistics": stats
    }


@app.get("/api/users")
async def list_users(
    user: User = Depends(require_permission("manage_roles")),
    db: Session = Depends(get_db)
):
    """List all users (Admin only)."""
    users = db.query(User).all()
    user_list = []
    for u in users:
        user_list.append({
            'user_id': u.user_id,
            'username': u.username,
            'role': u.role.value,
            'created_at': u.created_at.isoformat()
        })
    
    return {
        "status": "success",
        "users": user_list
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "SecureDocs API"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
