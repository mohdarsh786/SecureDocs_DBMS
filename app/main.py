"""
Main FastAPI application for SecureDocs.
Provides REST API endpoints for authentication and file management.
"""
import os
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File as FastAPIFile, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import BaseModel
from io import BytesIO

from app.models import User, File, UserRole, FilePermission
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


class LoginRequest(BaseModel):
    username: str
    password: str


class RenameRequest(BaseModel):
    new_filename: str


class RoleUpdateRequest(BaseModel):
    user_id: int
    role: str


class PermissionRequest(BaseModel):
    file_id: int
    user_id: int
    can_view: bool
    can_download: bool


@app.post("/api/register")
async def register(request: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new user with hashed password. All new users are Standard Users."""
    try:
        # All new users are registered as Standard User
        user = register_user(db, request.username, request.password, UserRole.USER)
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
    req: Request,
    file: UploadFile = FastAPIFile(...),
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
    file_list = []
    
    if user.role == UserRole.ADMIN or user.role == UserRole.MANAGER:
        # Admin and Manager can see all files
        files = db.query(File).filter(File.is_deleted == 0).all()
    else:
        # Standard User can see:
        # 1. Files they own
        own_files = db.query(File).filter(
            File.owner_id == user.user_id,
            File.is_deleted == 0
        ).all()
        
        # 2. Files they have view permission for
        permissions = db.query(FilePermission).filter(
            FilePermission.user_id == user.user_id,
            FilePermission.can_view == 1
        ).all()
        
        permitted_file_ids = [p.file_id for p in permissions]
        permitted_files = db.query(File).filter(
            File.file_id.in_(permitted_file_ids),
            File.is_deleted == 0
        ).all() if permitted_file_ids else []
        
        # Combine both lists
        files = own_files + permitted_files
    
    for f in files:
        # Check if user has download permission
        can_download = False
        if user.role in [UserRole.ADMIN, UserRole.MANAGER] or f.owner_id == user.user_id:
            can_download = True
        else:
            perm = db.query(FilePermission).filter(
                FilePermission.file_id == f.file_id,
                FilePermission.user_id == user.user_id,
                FilePermission.can_download == 1
            ).first()
            can_download = perm is not None
        
        file_list.append({
            'file_id': f.file_id,
            'filename': f.filename,
            'size': f.size,
            'owner_id': f.owner_id,
            'version': f.version,
            'created_at': f.created_at.isoformat(),
            'checksum': f.checksum,
            'can_download': can_download
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
    
    # Check access permissions
    has_access = False
    
    # Admin and Manager can download any file
    if user.role in [UserRole.ADMIN, UserRole.MANAGER]:
        has_access = True
    # Owner can download their own files
    elif file_record.owner_id == user.user_id:
        has_access = True
    # Standard User must have download permission
    else:
        perm = db.query(FilePermission).filter(
            FilePermission.file_id == file_id,
            FilePermission.user_id == user.user_id,
            FilePermission.can_download == 1
        ).first()
        has_access = perm is not None
    
    if not has_access:
        raise HTTPException(status_code=403, detail="Access denied: No download permission")
    
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
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all users (Admin and Manager only)."""
    # Allow both Admin and Manager to view users
    if user.role not in [UserRole.ADMIN, UserRole.MANAGER]:
        raise HTTPException(status_code=403, detail="Access denied. Admin or Manager role required.")
    
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


@app.put("/api/users/{user_id}/role")
async def update_user_role(
    user_id: int,
    request: RoleUpdateRequest,
    req: Request,
    user: User = Depends(require_permission("manage_roles")),
    db: Session = Depends(get_db)
):
    """Admin can assign roles to users (Manager or Standard User only)."""
    if user_id != request.user_id:
        raise HTTPException(status_code=400, detail="User ID mismatch")
    
    target_user = db.query(User).filter(User.user_id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent admin from changing their own role
    if target_user.user_id == user.user_id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")
    
    # Prevent changing existing Admin users
    if target_user.role == UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Cannot modify Admin accounts")
    
    # Only allow Manager and Standard User roles
    role_mapping = {
        "Manager": UserRole.MANAGER,
        "Standard User": UserRole.USER
    }
    
    new_role = role_mapping.get(request.role)
    if not new_role:
        raise HTTPException(status_code=400, detail="Invalid role. Only 'Manager' or 'Standard User' allowed")
    
    target_user.role = new_role
    db.commit()
    
    ip_address = get_client_ip(req)
    log_action(db, user.user_id, "ROLE_UPDATE", None, ip_address, 
              f"Changed user {target_user.username} role to {new_role.value}")
    
    return {
        "status": "success",
        "message": f"User role updated to {new_role.value}",
        "user": {
            "user_id": target_user.user_id,
            "username": target_user.username,
            "role": target_user.role.value
        }
    }


@app.delete("/api/users/{user_id}")
async def delete_user(
    user_id: int,
    req: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Admin can delete any user (except Admins), Manager can delete Standard Users."""
    target_user = db.query(User).filter(User.user_id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Prevent deleting yourself
    if target_user.user_id == user.user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    # Prevent deleting Admin accounts
    if target_user.role == UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Cannot delete Admin accounts")
    
    # Admin can delete anyone (except other Admins)
    if user.role == UserRole.ADMIN:
        pass
    # Manager can only delete Standard Users
    elif user.role == UserRole.MANAGER:
        if target_user.role != UserRole.USER:
            raise HTTPException(status_code=403, detail="Managers can only delete Standard Users")
    else:
        raise HTTPException(status_code=403, detail="Access denied")
    
    username = target_user.username
    db.delete(target_user)
    db.commit()
    
    ip_address = get_client_ip(req)
    log_action(db, user.user_id, "USER_DELETE", None, ip_address, f"Deleted user {username}")
    
    return {
        "status": "success",
        "message": f"User {username} deleted successfully"
    }


@app.put("/api/users/{user_id}/promote")
async def promote_user(
    user_id: int,
    req: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Manager can promote a Standard User to Manager."""
    if user.role != UserRole.MANAGER and user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only Managers and Admins can promote users")
    
    target_user = db.query(User).filter(User.user_id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if target_user.role != UserRole.USER:
        raise HTTPException(status_code=400, detail="Can only promote Standard Users")
    
    target_user.role = UserRole.MANAGER
    db.commit()
    
    ip_address = get_client_ip(req)
    log_action(db, user.user_id, "USER_PROMOTE", None, ip_address, 
              f"Promoted user {target_user.username} to Manager")
    
    return {
        "status": "success",
        "message": f"User {target_user.username} promoted to Manager",
        "user": {
            "user_id": target_user.user_id,
            "username": target_user.username,
            "role": target_user.role.value
        }
    }


@app.post("/api/files/permissions")
async def grant_file_permission(
    request: PermissionRequest,
    req: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Manager grants file access to Standard Users."""
    if user.role not in [UserRole.MANAGER, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Only Managers and Admins can grant permissions")
    
    file_record = db.query(File).filter(File.file_id == request.file_id, File.is_deleted == 0).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")
    
    target_user = db.query(User).filter(User.user_id == request.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if permission already exists
    existing_perm = db.query(FilePermission).filter(
        FilePermission.file_id == request.file_id,
        FilePermission.user_id == request.user_id
    ).first()
    
    if existing_perm:
        # Update existing permission
        existing_perm.can_view = 1 if request.can_view else 0
        existing_perm.can_download = 1 if request.can_download else 0
        existing_perm.granted_by = user.user_id
        existing_perm.granted_at = datetime.utcnow()
    else:
        # Create new permission
        new_perm = FilePermission(
            file_id=request.file_id,
            user_id=request.user_id,
            can_view=1 if request.can_view else 0,
            can_download=1 if request.can_download else 0,
            granted_by=user.user_id
        )
        db.add(new_perm)
    
    db.commit()
    
    ip_address = get_client_ip(req)
    log_action(db, user.user_id, "GRANT_PERMISSION", request.file_id, ip_address,
              f"Granted permissions to user {target_user.username}")
    
    return {
        "status": "success",
        "message": "File permissions updated successfully"
    }


@app.delete("/api/files/permissions/{file_id}/{user_id}")
async def revoke_file_permission(
    file_id: int,
    user_id: int,
    req: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Manager revokes file access from Standard Users."""
    if user.role not in [UserRole.MANAGER, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Only Managers and Admins can revoke permissions")
    
    permission = db.query(FilePermission).filter(
        FilePermission.file_id == file_id,
        FilePermission.user_id == user_id
    ).first()
    
    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")
    
    db.delete(permission)
    db.commit()
    
    ip_address = get_client_ip(req)
    log_action(db, user.user_id, "REVOKE_PERMISSION", file_id, ip_address,
              f"Revoked permissions from user ID {user_id}")
    
    return {
        "status": "success",
        "message": "File permissions revoked successfully"
    }


@app.get("/api/files/permissions/{file_id}")
async def get_file_permissions(
    file_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all permissions for a specific file (Manager/Admin only)."""
    if user.role not in [UserRole.MANAGER, UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Access denied")
    
    permissions = db.query(FilePermission).filter(FilePermission.file_id == file_id).all()
    
    perm_list = []
    for perm in permissions:
        target_user = db.query(User).filter(User.user_id == perm.user_id).first()
        if target_user:
            perm_list.append({
                'user_id': perm.user_id,
                'username': target_user.username,
                'can_view': bool(perm.can_view),
                'can_download': bool(perm.can_download),
                'granted_at': perm.granted_at.isoformat()
            })
    
    return {
        "status": "success",
        "permissions": perm_list
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
