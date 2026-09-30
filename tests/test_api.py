import unittest
import sys
import os
import json
import tempfile
from unittest.mock import patch

# Allow importing from the parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
from database import create_alert, init_db

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

    def test_alert_source_can_be_blocked_and_unblocked(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = os.path.join(temp_dir, 'test.db')
            with patch('database.DB_PATH', database_path):
                init_db()
                alert_id = create_alert(
                    'port_scan', 'HIGH', '203.0.113.42', {'reason': 'test'}
                )

                response = self.app.post(f'/alerts/{alert_id}/block-source')
                self.assertEqual(response.status_code, 201)
                block_id = response.get_json()['blocked_ip']['id']

                response = self.app.get('/ip-blocklist')
                self.assertEqual(response.status_code, 200)
                self.assertEqual(
                    response.get_json()['blocked_ips'][0]['source_ip'],
                    '203.0.113.42',
                )

                response = self.app.delete(f'/ip-blocklist/{block_id}')
                self.assertEqual(response.status_code, 200)
                self.assertEqual(self.app.get('/ip-blocklist').get_json()['blocked_ips'], [])

    def test_alert_with_invalid_source_ip_cannot_be_blocked(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('database.DB_PATH', os.path.join(temp_dir, 'test.db')):
                init_db()
                alert_id = create_alert(
                    'test', 'HIGH', 'not-an-ip', {'reason': 'test'}
                )

                response = self.app.post(f'/alerts/{alert_id}/block-source')
                self.assertEqual(response.status_code, 400)
                self.assertEqual(self.app.get('/ip-blocklist').get_json()['blocked_ips'], [])

    def test_high_severity_alert_auto_blocks_source_ip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('database.DB_PATH', os.path.join(temp_dir, 'test.db')):
                init_db()
                alert_id = create_alert(
                    'brute_force', 'HIGH', '198.51.100.99', {'reason': 'test'}
                )
                self.assertIsNotNone(alert_id)
                blocked = self.app.get('/ip-blocklist').get_json()['blocked_ips']
                self.assertTrue(any(entry['source_ip'] == '198.51.100.99' for entry in blocked))

    def test_network_model_training_endpoint(self):
        from ml import train_model

        with patch.object(train_model, 'train_and_compare') as mock_train:
            response = self.app.post('/ml/train')
        self.assertEqual(response.status_code, 200)
        mock_train.assert_called_once_with()

if __name__ == '__main__':
    unittest.main()
