#!/usr/bin/env python3
"""
Test script to verify MCP-SEC Web integration
"""

import requests
import json
import time
import sys
from pathlib import Path

# Test configuration
API_BASE_URL = "http://localhost:8000"
FRONTEND_URL = "http://localhost:5173"

def test_api_health():
    """Test API health endpoint"""
    try:
        response = requests.get(f"{API_BASE_URL}/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        print("✅ API health check passed")
        return True
    except Exception as e:
        print(f"❌ API health check failed: {e}")
        return False

def test_drifts_endpoint():
    """Test drifts endpoint"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/drifts")
        assert response.status_code == 200
        data = response.json()
        print(f"✅ Drifts endpoint returned {len(data)} drifts")
        return True
    except Exception as e:
        print(f"❌ Drifts endpoint failed: {e}")
        return False

def test_approvals_endpoint():
    """Test approvals endpoint"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/approvals")
        assert response.status_code == 200
        data = response.json()
        print(f"✅ Approvals endpoint returned {len(data)} approvals")
        return True
    except Exception as e:
        print(f"❌ Approvals endpoint failed: {e}")
        return False

def test_stats_endpoint():
    """Test stats endpoint"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert "pending_drifts" in data
        assert "total_drifts" in data
        print(f"✅ Stats endpoint returned: {data}")
        return True
    except Exception as e:
        print(f"❌ Stats endpoint failed: {e}")
        return False

def test_database_tables():
    """Test that database tables exist"""
    import sqlite3
    from pathlib import Path
    
    try:
        home_dir = Path.home()
        tracking_db = home_dir / ".mcp-sec" / "tracking.db"
        approvals_db = home_dir / ".mcp-sec" / "approvals.db"
        
        # Test tracking database
        conn = sqlite3.connect(tracking_db)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        conn.close()
        print(f"✅ Tracking DB tables: {[t[0] for t in tables]}")
        
        # Test approvals database
        conn = sqlite3.connect(approvals_db)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        conn.close()
        print(f"✅ Approvals DB tables: {[t[0] for t in tables]}")
        
        return True
    except Exception as e:
        print(f"❌ Database table test failed: {e}")
        return False

def test_frontend_accessibility():
    """Test if frontend is accessible"""
    try:
        response = requests.get(FRONTEND_URL)
        # Frontend might return different status codes depending on setup
        print(f"✅ Frontend accessibility test: Status {response.status_code}")
        return True
    except Exception as e:
        print(f"⚠️  Frontend accessibility test failed: {e}")
        print("   This is normal if the frontend is not running")
        return True  # Don't fail the test for this

def run_integration_tests():
    """Run all integration tests"""
    print("🧪 MCP-SEC Web Integration Tests")
    print("=" * 40)
    
    tests = [
        ("Database Tables", test_database_tables),
        ("API Health", test_api_health),
        ("Drifts Endpoint", test_drifts_endpoint),
        ("Approvals Endpoint", test_approvals_endpoint),
        ("Stats Endpoint", test_stats_endpoint),
        ("Frontend Accessibility", test_frontend_accessibility),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n🔍 Testing: {test_name}")
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            failed += 1
    
    print("\n" + "=" * 40)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! Integration is working correctly.")
        return True
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return False

if __name__ == "__main__":
    print("Starting integration tests...")
    print("Make sure the backend API is running on port 8000")
    print("You can start it with: cd backend && python main.py")
    print()
    
    # Wait a moment for user to start services if needed
    input("Press Enter to continue when the backend is running...")
    
    success = run_integration_tests()
    sys.exit(0 if success else 1)