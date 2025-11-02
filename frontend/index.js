/**
 * Main entry point for SecureDocs frontend.
 * Handles routing and application initialization.
 */

const API_BASE_URL = 'http://localhost:8000/api';

let currentUser = null;

function init() {
    const token = localStorage.getItem('jwt');
    if (token) {
        loadDashboard();
    } else {
        showLogin();
    }
}

function showLogin() {
    const app = document.getElementById('app');
    app.innerHTML = `
        <div class="auth-container">
            <h1>SecureDocs</h1>
            <div id="auth-form"></div>
        </div>
    `;
    renderLoginForm();
}

function renderLoginForm() {
    const authForm = document.getElementById('auth-form');
    authForm.innerHTML = `
        <div class="form-container">
            <h2>Login</h2>
            <div class="input-group">
                <input type="text" id="username" placeholder="Username" />
                <span class="error-message" id="username-error"></span>
            </div>
            <div class="input-group">
                <input type="password" id="password" placeholder="Password" />
                <span class="error-message" id="password-error"></span>
            </div>
            <button onclick="login()">Login</button>
            <p>Don't have an account? <a href="#" onclick="renderRegisterForm()">Register</a></p>
        </div>
    `;
}

function renderRegisterForm() {
    const authForm = document.getElementById('auth-form');
    authForm.innerHTML = `
        <div class="form-container">
            <h2>Register</h2>
            <div class="input-group">
                <input type="text" id="username" placeholder="Username" oninput="validateUsernameInput()" />
                <span class="error-message" id="username-error"></span>
            </div>
            <div class="password-requirements">
                <small>Username must:</small>
                <ul>
                    <li>Start with a letter</li>
                    <li>Contain only letters and numbers</li>
                    <li>Be at least 3 characters long</li>
                </ul>
            </div>
            <div class="input-group">
                <input type="password" id="password" placeholder="Password" oninput="validatePasswordInput()" />
                <span class="error-message" id="password-error"></span>
            </div>
            <div class="password-requirements">
                <small>Password must:</small>
                <ul>
                    <li>Be at least 8 characters long</li>
                    <li>Contain at least one uppercase letter</li>
                    <li>Contain at least one number</li>
                </ul>
            </div>
            <button onclick="register()">Register</button>
            <p>Already have an account? <a href="#" onclick="renderLoginForm()">Login</a></p>
        </div>
    `;
}

function validateUsernameInput() {
    const username = document.getElementById('username').value;
    const usernameError = document.getElementById('username-error');
    const usernameInput = document.getElementById('username');
    
    if (username.length === 0) {
        usernameInput.classList.remove('error');
        usernameError.textContent = '';
        return false;
    }
    
    if (username.length < 3) {
        usernameInput.classList.add('error');
        usernameError.textContent = 'At least 3 characters';
        return false;
    }
    
    if (!/^[a-zA-Z]/.test(username)) {
        usernameInput.classList.add('error');
        usernameError.textContent = 'Must start with a letter';
        return false;
    }
    
    if (!/^[a-zA-Z][a-zA-Z0-9]*$/.test(username)) {
        usernameInput.classList.add('error');
        usernameError.textContent = 'Only letters and numbers';
        return false;
    }
    
    usernameInput.classList.remove('error');
    usernameError.textContent = '';
    return true;
}

function validatePasswordInput() {
    const password = document.getElementById('password').value;
    const passwordError = document.getElementById('password-error');
    const passwordInput = document.getElementById('password');
    
    if (password.length === 0) {
        passwordInput.classList.remove('error');
        passwordError.textContent = '';
        return false;
    }
    
    const errors = [];
    
    if (password.length < 8) {
        errors.push('8+ chars');
    }
    
    if (!/[A-Z]/.test(password)) {
        errors.push('1 uppercase');
    }
    
    if (!/[0-9]/.test(password)) {
        errors.push('1 number');
    }
    
    if (errors.length > 0) {
        passwordInput.classList.add('error');
        passwordError.textContent = 'Need: ' + errors.join(', ');
        return false;
    }
    
    passwordInput.classList.remove('error');
    passwordError.textContent = '';
    return true;
}

async function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();
        if (response.ok) {
            localStorage.setItem('jwt', data.access_token);
            localStorage.setItem('user', JSON.stringify(data.user));
            currentUser = data.user;
            loadDashboard();
        } else {
            alert(data.detail || 'Login failed');
        }
    } catch (error) {
        alert('Login error: ' + error.message);
    }
}

async function register() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Validate inputs before submitting
    const isUsernameValid = validateUsernameInput();
    const isPasswordValid = validatePasswordInput();
    
    if (!isUsernameValid || !isPasswordValid) {
        alert('Please fix the validation errors before registering');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();
        if (response.ok) {
            alert('Registration successful! Please login.');
            renderLoginForm();
        } else {
            alert(data.detail || 'Registration failed');
        }
    } catch (error) {
        alert('Registration error: ' + error.message);
    }
}

function logout() {
    localStorage.removeItem('jwt');
    localStorage.removeItem('user');
    currentUser = null;
    showLogin();
}

function loadDashboard() {
    currentUser = JSON.parse(localStorage.getItem('user'));
    const app = document.getElementById('app');
    app.innerHTML = `
        <div class="dashboard">
            <div class="header">
                <h1>SecureDocs Dashboard</h1>
                <div class="user-info">
                    <span>Welcome, ${currentUser.username} (${currentUser.role})</span>
                    <button onclick="logout()">Logout</button>
                </div>
            </div>
            <div class="nav">
                <button onclick="showFiles()">Files</button>
                <button onclick="showUpload()">Upload</button>
                ${currentUser.role === 'Admin' || currentUser.role === 'Manager' ? '<button onclick="showAuditLogs()">Audit Logs</button>' : ''}
                ${currentUser.role === 'Admin' || currentUser.role === 'Manager' ? '<button onclick="showUsers()">Users</button>' : ''}
            </div>
            <div id="content"></div>
        </div>
    `;
    showFiles();
}

async function showFiles() {
    const content = document.getElementById('content');
    content.innerHTML = '<h2>My Files</h2><div id="file-list">Loading...</div>';

    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/files`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();
        if (response.ok) {
            renderFileList(data.files);
        } else {
            content.innerHTML = '<p>Error loading files</p>';
        }
    } catch (error) {
        content.innerHTML = '<p>Error: ' + error.message + '</p>';
    }
}

function renderFileList(files) {
    const fileList = document.getElementById('file-list');
    if (files.length === 0) {
        fileList.innerHTML = '<p>No files found</p>';
        return;
    }

    const userRole = currentUser.role;
    let html = '<table><tr><th>Filename</th><th>Size</th><th>Version</th><th>Created</th><th>Actions</th></tr>';
    files.forEach(file => {
        const canDownload = file.can_download !== undefined ? file.can_download : true;
        const downloadBtn = canDownload ? 
            `<button onclick="downloadFile(${file.file_id}, '${file.filename}')">Download</button>` :
            `<button disabled title="No download permission">Download</button>`;
        
        const isOwner = file.owner_id === currentUser.user_id;
        const canManage = userRole === 'Admin' || userRole === 'Manager' || isOwner;
        
        let actions = downloadBtn;
        if (canManage) {
            actions += `
                <button onclick="renameFile(${file.file_id}, '${file.filename}')">Rename</button>
                <button onclick="deleteFile(${file.file_id})">Delete</button>
            `;
        }
        
        if (userRole === 'Manager' || userRole === 'Admin') {
            actions += `<button onclick="manageFilePermissions(${file.file_id}, '${file.filename}')">Permissions</button>`;
        }
        
        html += `
            <tr>
                <td>${file.filename}</td>
                <td>${formatFileSize(file.size)}</td>
                <td>${file.version}</td>
                <td>${new Date(file.created_at).toLocaleString()}</td>
                <td>${actions}</td>
            </tr>
        `;
    });
    html += '</table>';
    fileList.innerHTML = html;
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

function showUpload() {
    const content = document.getElementById('content');
    content.innerHTML = `
        <h2>Upload File</h2>
        <div class="upload-form">
            <input type="file" id="file-input" />
            <button onclick="uploadFile()">Upload</button>
        </div>
    `;
}

async function uploadFile() {
    const fileInput = document.getElementById('file-input');
    const file = fileInput.files[0];

    if (!file) {
        alert('Please select a file');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` },
            body: formData
        });

        const data = await response.json();
        if (response.ok) {
            alert('File uploaded successfully');
            showFiles();
        } else {
            alert(data.detail || 'Upload failed');
        }
    } catch (error) {
        alert('Upload error: ' + error.message);
    }
}

async function downloadFile(fileId, filename) {
    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/download/${fileId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
        } else {
            alert('Download failed');
        }
    } catch (error) {
        alert('Download error: ' + error.message);
    }
}

async function renameFile(fileId, currentName) {
    const newName = prompt('Enter new filename:', currentName);
    if (!newName) return;

    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/files/${fileId}/rename`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ new_filename: newName })
        });

        const data = await response.json();
        if (response.ok) {
            alert('File renamed successfully');
            showFiles();
        } else {
            alert(data.detail || 'Rename failed');
        }
    } catch (error) {
        alert('Rename error: ' + error.message);
    }
}

async function deleteFile(fileId) {
    if (!confirm('Are you sure you want to delete this file?')) return;

    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/files/${fileId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();
        if (response.ok) {
            alert('File deleted successfully');
            showFiles();
        } else {
            alert(data.detail || 'Delete failed');
        }
    } catch (error) {
        alert('Delete error: ' + error.message);
    }
}

async function showAuditLogs() {
    const content = document.getElementById('content');
    content.innerHTML = `
        <h2>Audit Logs</h2>
        <div class="audit-controls">
            <button onclick="exportLogsJSON()">Export JSON</button>
            <button onclick="exportLogsCSV()">Export CSV</button>
        </div>
        <div id="audit-list">Loading...</div>
    `;

    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/audit/logs`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();
        if (response.ok) {
            renderAuditLogs(data.logs);
        } else {
            content.innerHTML = '<p>Error loading audit logs</p>';
        }
    } catch (error) {
        content.innerHTML = '<p>Error: ' + error.message + '</p>';
    }
}

function renderAuditLogs(logs) {
    const auditList = document.getElementById('audit-list');
    if (logs.length === 0) {
        auditList.innerHTML = '<p>No audit logs found</p>';
        return;
    }

    let html = '<table><tr><th>User</th><th>Role</th><th>Action</th><th>File</th><th>IP</th><th>Timestamp</th></tr>';
    logs.forEach(log => {
        html += `
            <tr>
                <td>${log.username}</td>
                <td>${log.role}</td>
                <td>${log.action}</td>
                <td>${log.filename || '-'}</td>
                <td>${log.ip_address}</td>
                <td>${new Date(log.timestamp).toLocaleString()}</td>
            </tr>
        `;
    });
    html += '</table>';
    auditList.innerHTML = html;
}

async function exportLogsJSON() {
    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/audit/export/json`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'audit_logs.json';
            document.body.appendChild(a);
            a.click();
            a.remove();
        }
    } catch (error) {
        alert('Export error: ' + error.message);
    }
}

async function exportLogsCSV() {
    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/audit/export/csv`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'audit_logs.csv';
            document.body.appendChild(a);
            a.click();
            a.remove();
        }
    } catch (error) {
        alert('Export error: ' + error.message);
    }
}

async function showUsers() {
    const content = document.getElementById('content');
    const userRole = currentUser.role;
    
    // Create tabs for different views
    let tabs = '';
    if (userRole === 'Manager') {
        tabs = `
            <div class="tabs">
                <button class="tab-btn active" onclick="showUserListTab()">User List</button>
                <button class="tab-btn" onclick="showFilePermissionsTab()">File Permissions</button>
            </div>
        `;
    }
    
    content.innerHTML = `
        <h2>User Management</h2>
        ${tabs}
        <div id="user-management-content">Loading...</div>
    `;
    
    // Load the default tab
    if (userRole === 'Manager') {
        showUserListTab();
    } else {
        loadUserList();
    }
}

async function showUserListTab() {
    // Update active tab
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    if (event && event.target) {
        event.target.classList.add('active');
    } else {
        document.querySelector('.tab-btn').classList.add('active');
    }
    loadUserList();
}

async function loadUserList() {
    const userManagementContent = document.getElementById('user-management-content');
    userManagementContent.innerHTML = '<div id="user-list">Loading...</div>';

    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/users`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();
        if (response.ok) {
            renderUserList(data.users);
        } else {
            userManagementContent.innerHTML = '<p>Error loading users</p>';
        }
    } catch (error) {
        userManagementContent.innerHTML = '<p>Error: ' + error.message + '</p>';
    }
}

function renderUserList(users) {
    const userList = document.getElementById('user-list');
    if (users.length === 0) {
        userList.innerHTML = '<p>No users found</p>';
        return;
    }

    const currentUserRole = currentUser.role;
    let html = '<table><tr><th>Username</th><th>Role</th><th>Created</th><th>Actions</th></tr>';
    users.forEach(user => {
        // Don't show action buttons for current user or Admin users
        let actions = '';
        if (user.user_id !== currentUser.user_id && user.role !== 'Admin') {
            if (currentUserRole === 'Admin') {
                // Admin can change role (only Manager or Standard User) and delete non-Admin users
                actions = `
                    <select id="role-${user.user_id}" onchange="updateUserRole(${user.user_id})">
                        <option value="Standard User" ${user.role === 'Standard User' ? 'selected' : ''}>Standard User</option>
                        <option value="Manager" ${user.role === 'Manager' ? 'selected' : ''}>Manager</option>
                    </select>
                    <button onclick="deleteUser(${user.user_id}, '${user.username}')">Delete</button>
                `;
            } else if (currentUserRole === 'Manager') {
                // Manager can promote Standard Users and delete them
                if (user.role === 'Standard User') {
                    actions = `
                        <button onclick="promoteUser(${user.user_id}, '${user.username}')">Promote to Manager</button>
                        <button onclick="deleteUser(${user.user_id}, '${user.username}')">Delete</button>
                    `;
                }
            }
        } else if (user.role === 'Admin') {
            // Show "Protected" for Admin accounts
            actions = '<span style="color: #667eea; font-weight: bold;">Protected</span>';
        }
        
        html += `
            <tr>
                <td>${user.username}</td>
                <td>${user.role}</td>
                <td>${new Date(user.created_at).toLocaleString()}</td>
                <td>${actions}</td>
            </tr>
        `;
    });
    html += '</table>';
    userList.innerHTML = html;
}

async function updateUserRole(userId) {
    const newRole = document.getElementById(`role-${userId}`).value;
    
    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/users/${userId}/role`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ user_id: userId, role: newRole })
        });

        const data = await response.json();
        if (response.ok) {
            alert(`User role updated to ${newRole}`);
            showUsers(); // Refresh the list
        } else {
            alert(data.detail || 'Failed to update role');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function promoteUser(userId, username) {
    if (!confirm(`Promote ${username} to Manager?`)) return;

    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/users/${userId}/promote`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();
        if (response.ok) {
            alert(data.message);
            showUsers(); // Refresh the list
        } else {
            alert(data.detail || 'Failed to promote user');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function deleteUser(userId, username) {
    if (!confirm(`Delete user ${username}? This action cannot be undone.`)) return;

    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/users/${userId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();
        if (response.ok) {
            alert(data.message);
            showUsers(); // Refresh the list
        } else {
            alert(data.detail || 'Failed to delete user');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function showFilePermissionsTab() {
    // Update active tab
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    if (event && event.target) {
        event.target.classList.add('active');
    }
    
    const userManagementContent = document.getElementById('user-management-content');
    userManagementContent.innerHTML = '<div id="file-permissions-grid">Loading...</div>';
    
    try {
        const token = localStorage.getItem('jwt');
        
        // Fetch all files
        const filesResponse = await fetch(`${API_BASE_URL}/files`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!filesResponse.ok) {
            const errorData = await filesResponse.json();
            userManagementContent.innerHTML = `<p class="error">Error loading files: ${errorData.detail || 'Unknown error'}</p>`;
            return;
        }
        
        const filesData = await filesResponse.json();
        
        // Fetch all users
        const usersResponse = await fetch(`${API_BASE_URL}/users`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!usersResponse.ok) {
            const errorData = await usersResponse.json();
            userManagementContent.innerHTML = `<p class="error">Error loading users: ${errorData.detail || 'Unknown error'}</p>`;
            return;
        }
        
        const usersData = await usersResponse.json();
        renderFilePermissionsGrid(filesData.files, usersData.users);
    } catch (error) {
        console.error('Error loading file permissions tab:', error);
        userManagementContent.innerHTML = `<p class="error">Network error: ${error.message}. Please ensure the API server is running at ${API_BASE_URL}</p>`;
    }
}

async function renderFilePermissionsGrid(files, users) {
    const grid = document.getElementById('file-permissions-grid');
    
    // Filter to show only Standard Users
    const standardUsers = users.filter(u => u.role === 'Standard User');
    
    if (standardUsers.length === 0) {
        grid.innerHTML = '<p>No Standard Users to manage permissions for.</p>';
        return;
    }
    
    if (files.length === 0) {
        grid.innerHTML = '<p>No files available to manage permissions.</p>';
        return;
    }
    
    let html = `
        <div class="permissions-header">
            <p>Select a file and user to manage permissions:</p>
        </div>
        <div class="permission-selector">
            <label for="file-select">File:</label>
            <select id="file-select" onchange="loadFilePermissionsForFile()">
                <option value="">-- Select a file --</option>
    `;
    
    files.forEach(file => {
        html += `<option value="${file.file_id}">${file.filename} (ID: ${file.file_id})</option>`;
    });
    
    html += `
            </select>
        </div>
        <div id="permission-details"></div>
    `;
    
    grid.innerHTML = html;
}

async function loadFilePermissionsForFile() {
    const fileId = document.getElementById('file-select').value;
    const permDetails = document.getElementById('permission-details');
    
    if (!fileId) {
        permDetails.innerHTML = '';
        return;
    }
    
    permDetails.innerHTML = '<p>Loading permissions...</p>';
    
    try {
        const token = localStorage.getItem('jwt');
        
        // Fetch users
        const usersResponse = await fetch(`${API_BASE_URL}/users`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!usersResponse.ok) {
            const errorData = await usersResponse.json();
            permDetails.innerHTML = `<p class="error">Error loading users: ${errorData.detail || 'Unknown error'}</p>`;
            return;
        }
        
        const usersData = await usersResponse.json();
        
        // Fetch permissions for this file
        const permsResponse = await fetch(`${API_BASE_URL}/files/permissions/${fileId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!permsResponse.ok) {
            const errorData = await permsResponse.json();
            permDetails.innerHTML = `<p class="error">Error loading permissions: ${errorData.detail || 'Unknown error'}</p>`;
            return;
        }
        
        const permsData = await permsResponse.json();
        renderUserPermissionsTable(fileId, usersData.users, permsData.permissions);
    } catch (error) {
        console.error('Error loading file permissions:', error);
        permDetails.innerHTML = `<p class="error">Network error: ${error.message}. Please ensure the API server is running.</p>`;
    }
}

function renderUserPermissionsTable(fileId, users, permissions) {
    const permDetails = document.getElementById('permission-details');
    
    // Filter to show only Standard Users
    const standardUsers = users.filter(u => u.role === 'Standard User');
    
    if (standardUsers.length === 0) {
        permDetails.innerHTML = '<p>No Standard Users to manage permissions for.</p>';
        return;
    }
    
    // Create a map of existing permissions
    const permMap = {};
    permissions.forEach(p => {
        permMap[p.user_id] = p;
    });
    
    let html = '<h3>User Permissions</h3>';
    html += '<table><tr><th>User</th><th>Can View</th><th>Can Download</th><th>Actions</th></tr>';
    
    standardUsers.forEach(user => {
        const perm = permMap[user.user_id];
        const canView = perm ? perm.can_view : false;
        const canDownload = perm ? perm.can_download : false;
        
        html += `
            <tr>
                <td>${user.username}</td>
                <td>
                    <input type="checkbox" id="view-${fileId}-${user.user_id}" ${canView ? 'checked' : ''} />
                </td>
                <td>
                    <input type="checkbox" id="download-${fileId}-${user.user_id}" ${canDownload ? 'checked' : ''} />
                </td>
                <td>
                    <button onclick="updateFilePermission(${fileId}, ${user.user_id})">Update</button>
                    ${perm ? `<button onclick="revokeFilePermission(${fileId}, ${user.user_id})">Revoke All</button>` : ''}
                </td>
            </tr>
        `;
    });
    
    html += '</table>';
    permDetails.innerHTML = html;
}

async function updateFilePermission(fileId, userId) {
    const canView = document.getElementById(`view-${fileId}-${userId}`).checked;
    const canDownload = document.getElementById(`download-${fileId}-${userId}`).checked;
    
    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/files/permissions`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                file_id: fileId,
                user_id: userId,
                can_view: canView,
                can_download: canDownload
            })
        });

        const data = await response.json();
        if (response.ok) {
            alert('Permission updated successfully');
            loadFilePermissionsForFile(); // Refresh
        } else {
            alert(data.detail || 'Failed to update permission');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function revokeFilePermission(fileId, userId) {
    if (!confirm('Revoke all permissions for this user on this file?')) return;
    
    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/files/permissions/${fileId}/${userId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();
        if (response.ok) {
            alert('Permission revoked successfully');
            loadFilePermissionsForFile(); // Refresh
        } else {
            alert(data.detail || 'Failed to revoke permission');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function manageFilePermissions(fileId, filename) {
    const content = document.getElementById('content');
    content.innerHTML = `
        <h2>Manage Permissions for: ${filename}</h2>
        <div id="permission-section">Loading...</div>
    `;
    
    try {
        const token = localStorage.getItem('jwt');
        
        // Fetch all users
        const usersResponse = await fetch(`${API_BASE_URL}/users`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const usersData = await usersResponse.json();
        
        // Fetch current permissions for this file
        const permsResponse = await fetch(`${API_BASE_URL}/files/permissions/${fileId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const permsData = await permsResponse.json();
        
        if (usersResponse.ok && permsResponse.ok) {
            renderPermissionManager(fileId, usersData.users, permsData.permissions);
        } else {
            content.innerHTML = '<p>Error loading permission data</p>';
        }
    } catch (error) {
        content.innerHTML = '<p>Error: ' + error.message + '</p>';
    }
}

function renderPermissionManager(fileId, users, permissions) {
    const permSection = document.getElementById('permission-section');
    
    // Filter to show only Standard Users
    const standardUsers = users.filter(u => u.role === 'Standard User');
    
    if (standardUsers.length === 0) {
        permSection.innerHTML = '<p>No Standard Users to manage permissions for.</p>';
        return;
    }
    
    // Create a map of existing permissions
    const permMap = {};
    permissions.forEach(p => {
        permMap[p.user_id] = p;
    });
    
    let html = '<table><tr><th>User</th><th>Can View</th><th>Can Download</th><th>Actions</th></tr>';
    standardUsers.forEach(user => {
        const perm = permMap[user.user_id];
        const canView = perm ? perm.can_view : false;
        const canDownload = perm ? perm.can_download : false;
        
        html += `
            <tr>
                <td>${user.username}</td>
                <td>
                    <input type="checkbox" id="view-${user.user_id}" ${canView ? 'checked' : ''} />
                </td>
                <td>
                    <input type="checkbox" id="download-${user.user_id}" ${canDownload ? 'checked' : ''} />
                </td>
                <td>
                    <button onclick="updatePermission(${fileId}, ${user.user_id})">Update</button>
                    ${perm ? `<button onclick="revokePermission(${fileId}, ${user.user_id})">Revoke</button>` : ''}
                </td>
            </tr>
        `;
    });
    html += '</table>';
    html += '<br><button onclick="showFiles()">Back to Files</button>';
    permSection.innerHTML = html;
}

async function updatePermission(fileId, userId) {
    const canView = document.getElementById(`view-${userId}`).checked;
    const canDownload = document.getElementById(`download-${userId}`).checked;
    
    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/files/permissions`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                file_id: fileId,
                user_id: userId,
                can_view: canView,
                can_download: canDownload
            })
        });

        const data = await response.json();
        if (response.ok) {
            alert('Permission updated successfully');
        } else {
            alert(data.detail || 'Failed to update permission');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function revokePermission(fileId, userId) {
    if (!confirm('Revoke all permissions for this user?')) return;
    
    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/files/permissions/${fileId}/${userId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();
        if (response.ok) {
            alert('Permission revoked successfully');
            // Reload the permission manager
            const filename = document.querySelector('h2').textContent.split(': ')[1];
            manageFilePermissions(fileId, filename);
        } else {
            alert(data.detail || 'Failed to revoke permission');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

window.onload = init;
