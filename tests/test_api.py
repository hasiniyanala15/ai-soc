import unittest
import sys
import os
import json
from unittest.mock import patch

# Allow importing from the parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
from database import init_db

class TestAPI(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Run once before any tests to setup the test database."""
        init_db()

    def setUp(self):
        """Run before every individual test."""
        self.app = app.test_client()
        self.app.testing = True

    def test_health_endpoint(self):
        """Test the /health endpoint correctly connects to the database."""
        response = self.app.get('/health')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'healthy')
        self.assertEqual(data['database'], 'connected')

    @patch('app.process_alert')
    def test_investigate_api_success(self, mock_process_alert):
        """Test that the investigate API correctly handles a successful AI response."""
        # Mock the AI agent so we don't need real API keys or DB alerts for this test
        mock_process_alert.return_value = {
            "alert_summary": "Mock summary",
            "confidence_level": "High"
        }
        
        response = self.app.post('/alerts/1/investigate')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertEqual(data['message'], "Investigation complete")
        self.assertEqual(data['report']['alert_summary'], "Mock summary")

    @patch('app.process_alert')
    def test_investigate_api_missing_alert(self, mock_process_alert):
        """Test that the API gracefully handles an invalid/missing Alert ID."""
        # Simulate the agent returning a 404 error logic
        mock_process_alert.return_value = {"error": "Alert ID 999 not found."}
        
        response = self.app.post('/alerts/999/investigate')
        # We programmed app.py to return 404 if 'not found' is in the error message
        self.assertEqual(response.status_code, 404)
        
        data = json.loads(response.data)
        self.assertIn("error", data)

if __name__ == '__main__':
    unittest.main()
