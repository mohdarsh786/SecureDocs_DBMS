-- Database initialization script for SecureDocs
-- Creates all required tables with proper constraints for MySQL

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('Admin', 'Manager', 'Standard User') NOT NULL DEFAULT 'Standard User',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create files table
CREATE TABLE IF NOT EXISTS files (
    file_id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    size INT NOT NULL,
    owner_id INT NOT NULL,
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    checksum VARCHAR(64) NOT NULL,
    file_data LONGBLOB,
    is_deleted TINYINT NOT NULL DEFAULT 0,
    FOREIGN KEY (owner_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_files_owner (owner_id),
    INDEX idx_files_is_deleted (is_deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    file_id INT NULL,
    action VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    signature_hash VARCHAR(64) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES files(file_id) ON DELETE SET NULL,
    INDEX idx_audit_logs_user (user_id),
    INDEX idx_audit_logs_file (file_id),
    INDEX idx_audit_logs_timestamp (timestamp DESC),
    INDEX idx_audit_logs_action (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create file_permissions table for access control
CREATE TABLE IF NOT EXISTS file_permissions (
    permission_id INT AUTO_INCREMENT PRIMARY KEY,
    file_id INT NOT NULL,
    user_id INT NOT NULL,
    can_view TINYINT NOT NULL DEFAULT 0,
    can_download TINYINT NOT NULL DEFAULT 0,
    granted_by INT NOT NULL,
    granted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (file_id) REFERENCES files(file_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by) REFERENCES users(user_id) ON DELETE CASCADE,
    UNIQUE KEY unique_file_user (file_id, user_id),
    INDEX idx_file_permissions_file (file_id),
    INDEX idx_file_permissions_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create default admin users
-- Username: Arsh, Password: Password123##
-- Username: Yuvraj, Password: Password123##
-- Hashes generated using bcrypt with default rounds
INSERT INTO users (username, password_hash, role)
VALUES 
    ('Arsh', '$2b$12$tt2kxRED7zva90x8.p2YyO38Q3dlWGhwN5Ga4VZU0d/LzPlo8l3e6', 'Admin'),
    ('Yuvraj', '$2b$12$tt2kxRED7zva90x8.p2YyO38Q3dlWGhwN5Ga4VZU0d/LzPlo8l3e6', 'Admin')
ON DUPLICATE KEY UPDATE username=username;
