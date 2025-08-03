# MCP-SEC Web Integration

This document describes how the MCP-SEC Web UI integrates with the existing MCP Security Scanner without modifying the core mcp-sec code.

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React UI      │    │   FastAPI       │    │   MCP-SEC       │
│   (Frontend)    │◄──►│   Backend       │◄──►│   SQLite DBs    │
│   Port 5173     │    │   Port 8000     │    │   ~/.mcp-sec/   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Components

### 1. FastAPI Backend (`backend/main.py`)
- **Purpose**: Interface layer between UI and MCP-SEC databases
- **No Code Changes**: Reads existing SQLite databases without modification
- **Key Features**:
  - RESTful API endpoints for drifts and approvals
  - Direct SQLite database access
  - CORS enabled for React frontend
  - Real-time approval workflow integration

### 2. React Frontend (Updated Components)
- **Dashboard**: Real-time drift monitoring with live data
- **API Client**: Handles communication with FastAPI backend  
- **Approval Workflow**: Interactive drift approval interface
- **Export Functions**: CSV/JSON export of drift data

### 3. Database Integration
Uses existing MCP-SEC SQLite databases:
- `~/.mcp-sec/tracking.db` - Drift detection and notifications
- `~/.mcp-sec/approvals.db` - Approval workflow management

## API Endpoints

### Core Endpoints
- `GET /api/drifts` - Fetch all detected drifts
- `GET /api/approvals` - Get pending approval requests  
- `POST /api/drifts/{id}/approve` - Quick approve a drift
- `POST /api/approvals/{id}/action` - Process approval (approve/reject)
- `GET /api/stats` - Dashboard statistics

### Data Mapping
The integration maps MCP-SEC data models to web UI format:

```python
# MCP-SEC Notification → Web UI Drift
{
  "notification_id": "drift-abc123",
  "server_name": "file-server", 
  "change_type": "tool_modified",
  "details": {"tool_name": "read-file"},
  "old_hash": "sha256:abc...",
  "new_hash": "sha256:xyz..."
}
```

## Setup Instructions

### Prerequisites
- Python 3.8+
- Node.js 16+
- MCP Security Scanner installed

### Quick Start
```bash
cd mcp-sec-web
./start.sh
```

This script:
1. Creates Python virtual environment
2. Installs backend dependencies (FastAPI, etc.)
3. Installs frontend dependencies (React, etc.)
4. Starts both services concurrently

### Manual Setup

#### Backend
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

#### Frontend  
```bash
npm install
npm run dev
```

## Usage Workflow

### 1. Generate Test Data
First, run the Drift Cop scanner to populate the databases:
```bash
cd ../mcp-sec
python -m mcp_sec.cli scan-workspace /path/to/project
# Or if installed: driftcop scan-workspace /path/to/project
```

### 2. Access Web UI
- **Dashboard**: http://localhost:5173
- **API Documentation**: http://localhost:8000/docs

### 3. Approval Workflow
1. **View Drifts**: Dashboard shows all detected drifts
2. **Review Details**: Click drift to see detailed information  
3. **Approve/Reject**: Use Quick Approve or detailed approval process
4. **Track Status**: Real-time updates reflect approval status

## Features

### Dashboard
- **Real-time Monitoring**: Live drift detection results
- **Filtering**: By severity, environment, search terms
- **Sorting**: Multiple sort criteria (severity, age, repo)
- **Export**: CSV and JSON export functionality
- **Bulk Actions**: Select multiple drifts for batch approval

### Approval System  
- **Quick Approve**: Single-click drift approval
- **Detailed Review**: Full drift analysis in workbench view
- **Status Tracking**: Real-time approval status updates
- **History**: Complete audit trail of all approvals

### Integration Benefits
- **No Core Changes**: Zero modifications to mcp-sec codebase
- **Real-time Data**: Direct database access for live updates
- **Full Compatibility**: Works with existing approval workflows
- **Extensible**: Easy to add new features without breaking core functionality

## Database Schema

### Notifications Table (tracking.db)
```sql
CREATE TABLE notifications (
    notification_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    server_name TEXT NOT NULL,
    change_type TEXT NOT NULL,
    details TEXT NOT NULL,
    old_hash TEXT,
    new_hash TEXT,
    requires_approval BOOLEAN DEFAULT 1,
    acknowledged BOOLEAN DEFAULT 0
);
```

### Approval Requests Table (approvals.db)
```sql
CREATE TABLE approval_requests (
    request_id TEXT PRIMARY KEY,
    notification_id TEXT NOT NULL,
    server_name TEXT NOT NULL,
    change_type TEXT NOT NULL,
    change_summary TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    rejection_reason TEXT
);
```

## Configuration

### Environment Variables
```bash
# Backend API (optional)
MCPSEC_DB_PATH=/custom/path/to/.mcp-sec
API_HOST=0.0.0.0
API_PORT=8000

# Frontend (optional)  
VITE_API_URL=http://localhost:8000/api
```

### CORS Configuration
The backend is pre-configured to allow requests from:
- `http://localhost:5173` (Vite dev server)
- `http://localhost:3000` (Alternative React port)

## Troubleshooting

### Common Issues

1. **Database Not Found**
   - Ensure Drift Cop has been run at least once
   - Check `~/.mcp-sec/` directory exists
   - Run: `driftcop scan-workspace .`

2. **API Connection Failed**
   - Verify backend is running on port 8000
   - Check CORS configuration
   - Ensure no firewall blocking requests

3. **Empty Dashboard**
   - Generate test data with MCP scanner
   - Check database has notifications table
   - Verify API endpoints return data

4. **Approval Not Working**
   - Check approval requests table exists
   - Verify user permissions
   - Look at backend logs for errors

### Logs
- **Backend**: Check console output from `python main.py`
- **Frontend**: Check browser developer tools console
- **Database**: SQLite logs in `~/.mcp-sec/` directory

## Development

### Adding New Features
1. **Backend**: Add endpoints in `backend/main.py`
2. **Frontend**: Update components and API client
3. **Database**: Use existing schema, add views if needed

### Testing
```bash
# Backend tests
cd backend
python -m pytest

# Frontend tests  
npm test

# Integration tests
./test-integration.sh
```

## Security Considerations

- **Database Access**: Read-only access to existing databases
- **API Authentication**: Consider adding auth for production use
- **CORS**: Restrict origins in production environment  
- **Input Validation**: All API inputs are validated
- **Error Handling**: Sensitive information not exposed in errors

## Future Enhancements

1. **Real-time Updates**: WebSocket integration for live updates
2. **Advanced Filtering**: More sophisticated search and filter options
3. **Reporting**: Enhanced reporting and analytics features
4. **Authentication**: User management and role-based access
5. **Notifications**: Email/Slack integration for approval alerts