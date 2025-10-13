# SecureDocs - Running Code Guide

## Quick Start with Docker (Recommended)

### Prerequisites
- Docker Desktop installed and running
- Docker Compose installed

### Steps to Run

1. **Navigate to project directory**
   ```powershell
   cd "e:\SecureDocs_DBMS"
   ```

2. **Start all services**
   ```powershell
   docker-compose up --build
   ```

3. **Access the application**
   - Frontend: http://localhost
   - API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

4. **Default Admin Credentials**
   - Username: `admin`
   - Password: `admin123`

5. **Stop services**
   ```powershell
   docker-compose down
   ```

---

## Manual Setup (Without Docker)

### Prerequisites
- Python 3.11+
- MySQL 8.0+
- Node.js (for serving frontend)

### Backend Setup

1. **Install Python dependencies**
   ```powershell
   pip install -r requirements.txt
   ```

2. **Setup MySQL database**
   ```powershell
   # Create database
   mysql -u root -p
   CREATE DATABASE securedocs;
   EXIT;
   
   # Run initialization script
   mysql -u root -p securedocs < database\init.sql
   ```

3. **Configure environment variables**
   ```powershell
   # Copy example env file
   copy .env.example .env
   
   # Edit .env with your database credentials
   ```

4. **Run the API server**
   ```powershell
   cd "e:\SecureDocs_DBMS"
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

### Frontend Setup

1. **Serve frontend files**
   
   **Option A: Using Python HTTP server**
   ```powershell
   cd frontend
   python -m http.server 80
   ```
   
   **Option B: Using Node.js http-server**
   ```powershell
   npm install -g http-server
   cd frontend
   http-server -p 80
   ```

2. **Access frontend**
   - Open browser: http://localhost

---

## API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - Login and get JWT token

### File Management
- `GET /api/files` - List accessible files
- `POST /api/upload` - Upload a file
- `GET /api/download/{file_id}` - Download file
- `PUT /api/files/{file_id}/rename` - Rename file
- `DELETE /api/files/{file_id}` - Delete file (soft delete)

### Audit Logs (Admin/Manager only)
- `GET /api/audit/logs` - View audit logs
- `GET /api/audit/export/json` - Export logs as JSON
- `GET /api/audit/export/csv` - Export logs as CSV
- `GET /api/audit/statistics` - Get audit statistics

### User Management (Admin only)
- `GET /api/users` - List all users

### Health Check
- `GET /api/health` - API health status

---

## User Roles and Permissions

### Admin
- All file operations
- View audit logs
- Export audit logs
- Manage users and roles
- Access all files

### Manager
- Upload, download, rename, delete files
- View audit logs
- Export audit logs
- Access all files

### Standard User
- Upload files
- Download own files
- Rename own files (with Manager+ override)
- Delete own files (with Manager+ override)

---

## Example Usage

### Using the Frontend

1. **Register a new user**
   - Open http://localhost
   - Click "Register"
   - Enter username, password, and select role
   - Click "Register" button

2. **Login**
   - Enter credentials
   - Click "Login"

3. **Upload a file**
   - Click "Upload" in navigation
   - Select a file
   - Click "Upload" button

4. **Download a file**
   - Click "Files" in navigation
   - Click "Download" button on any file

5. **View audit logs** (Admin/Manager only)
   - Click "Audit Logs" in navigation
   - View all logged actions
   - Export to JSON or CSV

### Using the API Directly

**Register User**
```powershell
curl -X POST http://localhost:8000/api/register `
  -H "Content-Type: application/json" `
  -d '{"username":"testuser","password":"password123","role":"User"}'
```

**Login**
```powershell
curl -X POST http://localhost:8000/api/login `
  -H "Content-Type: application/json" `
  -d '{"username":"admin","password":"admin123"}'
```

**Upload File**
```powershell
curl -X POST http://localhost:8000/api/upload `
  -H "Authorization: Bearer YOUR_JWT_TOKEN" `
  -F "file=@path\to\file.txt"
```

**List Files**
```powershell
curl -X GET http://localhost:8000/api/files `
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

---

## Troubleshooting

### Database Connection Issues
- Ensure MySQL is running
- Check DATABASE_URL in .env or docker-compose.yml
- Verify database exists: `mysql -u root -p -e "SHOW DATABASES;"`

### Port Already in Use
```powershell
# Change ports in docker-compose.yml
# Frontend: Change "80:80" to "8080:80"
# API: Change "8000:8000" to "8001:8000"
```

### API Cannot Connect to Database
```powershell
# If using Docker, ensure containers are on same network
docker network ls
docker network inspect securedocs_network
```

### Frontend Cannot Reach API
- Update `API_BASE_URL` in `frontend/index.js` to match your API endpoint
- Ensure CORS is enabled (already configured in app/main.py)

---

## Development Mode

### Run API with Hot Reload
```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### View Logs
```powershell
# Docker logs
docker-compose logs -f api
docker-compose logs -f db
docker-compose logs -f frontend

# View specific service
docker-compose logs -f api
```

### Access Database
```powershell
# Via Docker
docker exec -it securedocs_db mysql -u admin -p securedocs

# Locally
mysql -u admin -p securedocs
```

---

## Stopping the Application

### Docker
```powershell
# Stop and remove containers
docker-compose down

# Stop and remove containers + volumes (deletes data)
docker-compose down -v
```

### Manual
```powershell
# Stop API: Ctrl+C in the terminal running uvicorn
# Stop frontend: Ctrl+C in the terminal running http-server
```

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| DATABASE_URL | mysql+pymysql://admin:password@db:3306/securedocs | MySQL connection string |
| JWT_SECRET | your_secret_key | Secret key for JWT signing |
| STORAGE_MODE | database | Storage backend (database/filesystem/s3) |
| STORAGE_PATH | ./file_storage | Path for filesystem storage |
| LOG_LEVEL | info | Logging level (debug/info/warning/error) |

---

## Next Steps

1. Change default admin password after first login
2. Update JWT_SECRET in production
3. Enable HTTPS for production deployment
4. Configure backup strategy for MySQL
5. Set up monitoring and logging
