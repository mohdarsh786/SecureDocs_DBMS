# Role-Based Access Control (RBAC) System - SecureDocs

## Overview
This document describes the comprehensive role-based access control system implemented in SecureDocs.

## System Changes

### 1. User Registration
- **Changed**: Role selection removed from registration page
- **Behavior**: All new users are automatically registered as "Standard User"
- **Access**: Only Admin can change user roles after registration

### 2. Role Hierarchy

#### Admin (Highest Privileges)
**Can:**
- View all files
- Download any file
- Assign roles (Manager or Standard User only) to non-Admin users
- Delete any user except Admin accounts
- Manage file permissions for non-Admin users
- View audit logs and statistics
- Upload, rename, and delete files

**Cannot:**
- Create new Admin accounts
- Delete Admin accounts
- Change Admin account roles
- Assign Admin role to any user

#### Manager (Middle Tier)
**Can:**
- View all files uploaded to the platform
- Download any file
- Upload, rename, and delete files
- Promote Standard Users to Manager role
- Delete Standard Users from the database
- Grant/revoke file view permissions to Standard Users
- Grant/revoke file download permissions to Standard Users
- View audit logs

#### Standard User (Basic Access)
**Can:**
- View only their own uploaded files
- View files that a Manager has explicitly granted them access to
- Download their own files
- Download files where Manager has granted download permission
- Upload new files
- Rename their own files
- Delete their own files

**Cannot:**
- View other users' files (unless granted permission)
- Download files without permission
- Manage other users
- Access audit logs

### 3. File Permission System

#### New Database Table: `file_permissions`
```sql
CREATE TABLE file_permissions (
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
    UNIQUE KEY unique_file_user (file_id, user_id)
)
```

#### Permission Types
1. **View Permission**: Allows a Standard User to see the file in their file list
2. **Download Permission**: Allows a Standard User to download the file

**Important**: Download permission is only effective if view permission is also granted.

### 4. New API Endpoints

#### User Management (Admin Only)
- `PUT /api/users/{user_id}/role` - Assign role to a user (Manager or Standard User only)
  ```json
  {
    "user_id": 123,
    "role": "Manager"  // Options: "Manager", "Standard User" (Admin not allowed)
  }
  ```

#### User Deletion
- `DELETE /api/users/{user_id}`
  - Admin: Can delete Managers and Standard Users (NOT other Admins)
  - Manager: Can delete Standard Users only

#### User Promotion (Manager/Admin)
- `PUT /api/users/{user_id}/promote` - Promote Standard User to Manager

#### File Permission Management (Manager/Admin)
- `POST /api/files/permissions` - Grant or update permissions
  ```json
  {
    "file_id": 456,
    "user_id": 123,
    "can_view": true,
    "can_download": true
  }
  ```

- `DELETE /api/files/permissions/{file_id}/{user_id}` - Revoke all permissions

- `GET /api/files/permissions/{file_id}` - List all permissions for a file

### 5. Modified Endpoints

#### File Listing (`GET /api/files`)
**Before**: All users saw all non-deleted files or only their own
**After**:
- Admin/Manager: See all files
- Standard User: See only:
  - Files they own
  - Files they have view permission for
- Response includes `can_download` flag for each file

#### File Download (`GET /api/download/{file_id}`)
**Before**: Admin/Manager could download any file, users only their own
**After**:
- Admin/Manager: Can download any file
- Standard User: Can download only if:
  - They own the file, OR
  - They have download permission granted by Manager

### 6. Frontend Changes

#### Registration Page
- Removed role selection dropdown
- All registrations create Standard Users by default

#### User Management (Admin Dashboard)
- Role dropdown for each user (only Manager and Standard User options)
- Delete button for each user (except current user and Admin accounts)
- Real-time role updates
- Admin accounts show "Protected" status

#### User Management (Manager Dashboard)
- "Promote to Manager" button for Standard Users
- "Delete" button for Standard Users
- No access to Admin accounts

#### File List Page
- "Permissions" button for Managers/Admins on each file
- Download button disabled for files without download permission
- Visual indication of permission status

#### Permission Management Page (Manager/Admin)
- Lists all Standard Users
- Checkboxes for View and Download permissions
- Update and Revoke buttons
- Real-time permission updates

### 7. Validation Rules

#### Username Validation
- Minimum 3 characters
- Must start with a letter
- Only alphanumeric characters (letters and numbers)

#### Password Validation
- Minimum 8 characters
- At least one uppercase letter
- At least one numeric digit

### 8. Audit Logging

New actions logged:
- `ROLE_UPDATE` - When Admin changes a user's role
- `USER_DELETE` - When Admin/Manager deletes a user
- `USER_PROMOTE` - When Manager promotes a user
- `GRANT_PERMISSION` - When Manager grants file permissions
- `REVOKE_PERMISSION` - When Manager revokes file permissions

All audit logs include:
- User who performed the action
- Timestamp
- IP address
- Additional details about the action

## Security Features

1. **Self-Protection**: Users cannot delete or change their own role
2. **Permission Cascade**: Deleting a file automatically removes all associated permissions
3. **User Cascade**: Deleting a user removes all their permissions
4. **Validation**: All inputs validated on both frontend and backend
5. **Audit Trail**: All administrative actions are logged

## Testing the System

### As Admin:
1. Login with admin credentials
2. Go to "Users" section
3. Change any user's role using the dropdown
4. Delete any user (except yourself)
5. Manage file permissions for any file

### As Manager:
1. Register as a new user (will be Standard User)
2. Have Admin promote you to Manager
3. Upload a file
4. Click "Permissions" on the file
5. Grant view/download permissions to Standard Users
6. Promote a Standard User to Manager
7. Delete a Standard User

### As Standard User:
1. Register as a new user
2. Upload a file
3. Verify you can only see your own files
4. Have Manager grant you permission to their file
5. Verify you can now see and/or download it (based on permissions)

## Database Migration

If upgrading from previous version:
1. The new `file_permissions` table will be created automatically
2. Existing users retain their roles
3. No data loss occurs
4. All existing files remain accessible to their owners

## Default Credentials

The system has exactly **two Admin accounts** that cannot be modified or deleted:

- **Username**: Arsh  
  **Password**: Password123##  
  **Role**: Admin

- **Username**: Yuvraj  
  **Password**: Password123##  
  **Role**: Admin

**Important Notes:**
- These are the only Admin accounts in the system
- Admin accounts cannot be deleted
- Admin accounts cannot have their roles changed
- No new Admin accounts can be created through any means
- Admins can only assign "Manager" or "Standard User" roles to other users

## Important Notes

1. **First Setup**: Create additional Manager accounts using Admin privileges
2. **File Ownership**: Files are always accessible to their owner regardless of permissions
3. **Permission Inheritance**: Managers can see all files but Standard Users need explicit permission
4. **Irreversible Actions**: User deletion cannot be undone (files are deleted via CASCADE)
5. **Permission Granularity**: View and Download are separate - you can allow viewing without downloading
