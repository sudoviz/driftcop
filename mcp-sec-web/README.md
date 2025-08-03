# MCP-SEC Web Integration

A modern web UI for the MCP Security Scanner with real-time approval workflows.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- MCP Security Scanner installed

### One-Command Setup
```bash
./start.sh
```

This will:
1. Install all dependencies
2. Start backend API on port 8000
3. Start frontend UI on port 5173
4. Open browser to dashboard

### Manual Setup

#### 1. Backend API
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

#### 2. Frontend UI
```bash
npm install
npm run dev
```

## 📊 Usage

### Generate Test Data
First, run the Drift Cop scanner to populate the databases:
```bash
cd ../mcp-sec
driftcop scan-workspace /path/to/your/project
```

### Access the Dashboard
- **Web UI**: http://localhost:5173
- **API Docs**: http://localhost:8000/docs

### Approval Workflow
1. **View Drifts**: Dashboard shows all detected configuration drifts
2. **Review Details**: Click any drift to see detailed analysis
3. **Approve Changes**: Use "Quick Approve" or detailed workflow
4. **Track Status**: Real-time updates show approval status

## 🎯 Features

### Dashboard
- ✅ Real-time drift monitoring
- ✅ Filtering by severity, environment, search
- ✅ Sortable columns (severity, age, repo, tool)
- ✅ Bulk selection and approval
- ✅ CSV/JSON export

### Approval System
- ✅ Interactive drift approval workflow
- ✅ Detailed change analysis
- ✅ Risk assessment and categorization
- ✅ Complete audit trail
- ✅ Real-time status updates

### Integration
- ✅ **Zero code changes** to mcp-sec codebase
- ✅ Direct database integration
- ✅ Full compatibility with existing workflows
- ✅ RESTful API with comprehensive documentation

## 🔧 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/drifts` | Fetch all detected drifts |
| GET | `/api/approvals` | Get pending approval requests |
| POST | `/api/drifts/{id}/approve` | Quick approve a drift |
| POST | `/api/approvals/{id}/action` | Process approval (approve/reject) |
| GET | `/api/stats` | Dashboard statistics |

## 🗄️ Database Integration

The integration uses existing MCP-SEC SQLite databases:
- `~/.mcp-sec/tracking.db` - Drift detection and notifications
- `~/.mcp-sec/approvals.db` - Approval workflow management

**No modifications** are made to the core mcp-sec codebase.

## 🧪 Testing

Run integration tests:
```bash
python test-integration.py
```

Tests verify:
- ✅ Database connectivity
- ✅ API endpoints functionality
- ✅ Frontend accessibility
- ✅ Approval workflow integration

## 📁 Project Structure

```
mcp-sec-web/
├── backend/                 # FastAPI backend
│   ├── main.py             # API server
│   ├── requirements.txt    # Python dependencies
│   └── venv/               # Virtual environment
├── src/                    # React frontend
│   ├── components/         # UI components
│   ├── lib/               # API client and utilities
│   ├── pages/             # Page components
│   └── types/             # TypeScript types
├── start.sh               # One-command setup script
├── test-integration.py    # Integration test suite
├── INTEGRATION.md         # Detailed integration docs
└── README.md             # This file
```

## 🔒 Security

- **Read-only access** to existing databases
- **Input validation** on all API endpoints
- **CORS protection** configured for localhost
- **Error handling** prevents information disclosure

## 🛠️ Development

### Adding Features
1. **Backend**: Add endpoints in `backend/main.py`
2. **Frontend**: Update components and API client
3. **Database**: Use existing schema, no migrations needed

### Environment Variables
```bash
# Optional configuration
MCPSEC_DB_PATH=/custom/path/to/.mcp-sec
API_HOST=0.0.0.0
API_PORT=8000
VITE_API_URL=http://localhost:8000/api
```

## 🐛 Troubleshooting

### Common Issues

**Database Not Found**
```bash
# Generate test data first
cd ../mcp-sec
driftcop scan-workspace .
```

**API Connection Failed**
```bash
# Check backend is running
curl http://localhost:8000/api/stats
```

**Empty Dashboard**
```bash
# Verify databases have data
ls -la ~/.mcp-sec/
```

**Dependency Conflicts**
```bash
# Clean install
rm -rf node_modules package-lock.json
npm install
```

## 📚 Documentation

- [INTEGRATION.md](./INTEGRATION.md) - Detailed integration guide
- [API Documentation](http://localhost:8000/docs) - Interactive API docs
- [MCP-SEC Documentation](../mcp-sec/README.md) - Core scanner docs

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with `python test-integration.py`
5. Submit a pull request

## 📝 License

This project follows the same license as the MCP Security Scanner.

---

## 🎉 Success!

The MCP-SEC Web Integration provides a modern, intuitive interface for managing configuration drift detection and approval workflows without requiring any changes to the core security scanner codebase.

**Next Steps:**
1. Run `./start.sh` to get started
2. Generate test data with the MCP scanner
3. Explore the dashboard and approval workflows
4. Customize for your organization's needs