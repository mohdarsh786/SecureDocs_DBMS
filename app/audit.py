"""
Audit logging module for SecureDocs.
Provides immutable logging and signed audit trail export functionality.
"""
import hashlib
import json
import csv
from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session
from app.models import AuditLog, User, File


def log_action(db: Session, user_id: int, action: str, file_id: Optional[int], ip_address: str) -> AuditLog:
    """
    Create an append-only audit log entry.
    Generates signature hash for immutability verification.
    """
    timestamp = datetime.utcnow()
    
    signature_data = f"{user_id}:{action}:{file_id}:{ip_address}:{timestamp.isoformat()}"
    signature_hash = hashlib.sha256(signature_data.encode('utf-8')).hexdigest()
    
    log_entry = AuditLog(
        user_id=user_id,
        file_id=file_id,
        action=action,
        ip_address=ip_address,
        timestamp=timestamp,
        signature_hash=signature_hash
    )
    
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    
    return log_entry


def get_audit_logs(db: Session, user_id: Optional[int] = None, action: Optional[str] = None, 
                   file_id: Optional[int] = None, limit: int = 100, offset: int = 0) -> List[dict]:
    """
    Retrieve audit logs with optional filtering.
    Returns formatted log entries for display.
    """
    query = db.query(AuditLog).join(User)
    
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if action:
        query = query.filter(AuditLog.action == action)
    if file_id:
        query = query.filter(AuditLog.file_id == file_id)
    
    logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset).all()
    
    result = []
    for log in logs:
        result.append({
            'log_id': log.log_id,
            'username': log.user.username,
            'role': log.user.role.value,
            'action': log.action,
            'file_id': log.file_id,
            'filename': log.file.filename if log.file else None,
            'ip_address': log.ip_address,
            'timestamp': log.timestamp.isoformat(),
            'signature_hash': log.signature_hash
        })
    
    return result


def verify_log_integrity(log_entry: AuditLog) -> bool:
    """
    Verify the integrity of an audit log entry.
    Recalculates signature hash and compares with stored value.
    """
    signature_data = f"{log_entry.user_id}:{log_entry.action}:{log_entry.file_id}:{log_entry.ip_address}:{log_entry.timestamp.isoformat()}"
    calculated_hash = hashlib.sha256(signature_data.encode('utf-8')).hexdigest()
    
    return calculated_hash == log_entry.signature_hash


def export_audit_logs_json(db: Session, user_id: Optional[int] = None, 
                           action: Optional[str] = None) -> str:
    """
    Export audit logs as signed JSON snapshot.
    Includes all log entries and overall signature for verification.
    """
    logs = get_audit_logs(db, user_id=user_id, action=action, limit=10000)
    
    export_data = {
        'export_timestamp': datetime.utcnow().isoformat(),
        'total_logs': len(logs),
        'logs': logs
    }
    
    logs_json = json.dumps(logs, sort_keys=True)
    overall_signature = hashlib.sha256(logs_json.encode('utf-8')).hexdigest()
    export_data['signature'] = overall_signature
    
    return json.dumps(export_data, indent=2)


def export_audit_logs_csv(db: Session, user_id: Optional[int] = None, 
                          action: Optional[str] = None) -> str:
    """
    Export audit logs as CSV format.
    Suitable for spreadsheet analysis and reporting.
    """
    logs = get_audit_logs(db, user_id=user_id, action=action, limit=10000)
    
    if not logs:
        return ""
    
    csv_lines = []
    headers = ['log_id', 'username', 'role', 'action', 'file_id', 'filename', 
               'ip_address', 'timestamp', 'signature_hash']
    csv_lines.append(','.join(headers))
    
    for log in logs:
        row = [
            str(log.get('log_id', '')),
            str(log.get('username', '')),
            str(log.get('role', '')),
            str(log.get('action', '')),
            str(log.get('file_id', '')),
            str(log.get('filename', '')),
            str(log.get('ip_address', '')),
            str(log.get('timestamp', '')),
            str(log.get('signature_hash', ''))
        ]
        csv_lines.append(','.join(row))
    
    return '\n'.join(csv_lines)


def get_audit_statistics(db: Session) -> dict:
    """
    Generate audit statistics for dashboard display.
    Returns counts and summaries of logged actions.
    """
    total_logs = db.query(AuditLog).count()
    
    action_counts = {}
    actions = db.query(AuditLog.action).distinct().all()
    for (action,) in actions:
        count = db.query(AuditLog).filter(AuditLog.action == action).count()
        action_counts[action] = count
    
    recent_logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    return {
        'total_logs': total_logs,
        'action_counts': action_counts,
        'recent_activity': len(recent_logs)
    }
