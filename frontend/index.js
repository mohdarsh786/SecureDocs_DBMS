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
            <input type="text" id="username" placeholder="Username" />
            <input type="password" id="password" placeholder="Password" />
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
            <input type="text" id="username" placeholder="Username" />
            <input type="password" id="password" placeholder="Password" />
            <select id="role">
                <option value="User">Standard User</option>
                <option value="Manager">Manager</option>
                <option value="Admin">Admin</option>
            </select>
            <button onclick="register()">Register</button>
            <p>Already have an account? <a href="#" onclick="renderLoginForm()">Login</a></p>
        </div>
    `;
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
    const role = document.getElementById('role').value;

    try {
        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, role })
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
                ${currentUser.role === 'Admin' ? '<button onclick="showUsers()">Users</button>' : ''}
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

    let html = '<table><tr><th>Filename</th><th>Size</th><th>Version</th><th>Created</th><th>Actions</th></tr>';
    files.forEach(file => {
        html += `
            <tr>
                <td>${file.filename}</td>
                <td>${formatFileSize(file.size)}</td>
                <td>${file.version}</td>
                <td>${new Date(file.created_at).toLocaleString()}</td>
                <td>
                    <button onclick="downloadFile(${file.file_id}, '${file.filename}')">Download</button>
                    <button onclick="renameFile(${file.file_id}, '${file.filename}')">Rename</button>
                    <button onclick="deleteFile(${file.file_id})">Delete</button>
                </td>
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
    content.innerHTML = '<h2>User Management</h2><div id="user-list">Loading...</div>';

    try {
        const token = localStorage.getItem('jwt');
        const response = await fetch(`${API_BASE_URL}/users`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const data = await response.json();
        if (response.ok) {
            renderUserList(data.users);
        } else {
            content.innerHTML = '<p>Error loading users</p>';
        }
    } catch (error) {
        content.innerHTML = '<p>Error: ' + error.message + '</p>';
    }
}

function renderUserList(users) {
    const userList = document.getElementById('user-list');
    if (users.length === 0) {
        userList.innerHTML = '<p>No users found</p>';
        return;
    }

    let html = '<table><tr><th>Username</th><th>Role</th><th>Created</th></tr>';
    users.forEach(user => {
        html += `
            <tr>
                <td>${user.username}</td>
                <td>${user.role}</td>
                <td>${new Date(user.created_at).toLocaleString()}</td>
            </tr>
        `;
    });
    html += '</table>';
    userList.innerHTML = html;
}

window.onload = init;
