#!/bin/bash

# MCP-SEC Web Integration Setup Script

set -e

echo "🚀 Starting MCP-SEC Web Integration"
echo "=================================="

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "❌ Error: Please run this script from the mcp-sec-web directory"
    exit 1
fi

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is required but not installed"
    exit 1
fi

# Check if Node.js is available
if ! command -v npm &> /dev/null; then
    echo "❌ Error: Node.js and npm are required but not installed"
    exit 1
fi

echo "📦 Installing dependencies..."

# Install Python backend dependencies
echo "Installing Python backend dependencies..."
cd backend
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate
pip install -r requirements.txt
cd ..

# Install frontend dependencies
echo "Installing frontend dependencies..."
npm install

echo "🔧 Setting up MCP-SEC integration..."

# Check if MCP-SEC databases exist
MCPSEC_DIR="$HOME/.mcp-sec"
TRACKING_DB="$MCPSEC_DIR/tracking.db"
APPROVALS_DB="$MCPSEC_DIR/approvals.db"

if [ ! -d "$MCPSEC_DIR" ]; then
    echo "Creating MCP-SEC directory: $MCPSEC_DIR"
    mkdir -p "$MCPSEC_DIR"
fi

# Initialize databases if they don't exist
if [ ! -f "$TRACKING_DB" ] || [ ! -f "$APPROVALS_DB" ]; then
    echo "⚠️  MCP-SEC databases not found. They will be created when the API starts."
    echo "   To get test data, run the MCP Security Scanner first:"
    echo "   cd ../mcp-sec && python -m mcp_sec.cli scan-workspace ."
fi

echo "✅ Setup complete!"
echo ""
echo "🌐 Starting services..."
echo "Backend API: http://localhost:8000"
echo "Frontend UI: http://localhost:5173"
echo ""

# Function to handle cleanup
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    exit 0
}

# Set trap to cleanup on exit
trap cleanup SIGINT SIGTERM

# Start backend API
echo "Starting backend API..."
cd backend
source venv/bin/activate
python main.py &
BACKEND_PID=$!
cd ..

# Wait a moment for the backend to start
sleep 2

# Start frontend
echo "Starting frontend..."
npm run dev &
FRONTEND_PID=$!

echo ""
echo "🎉 Services are running!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Dashboard: http://localhost:5173"
echo "🔌 API Docs: http://localhost:8000/docs"
echo "💾 Database: $MCPSEC_DIR"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for background processes
wait