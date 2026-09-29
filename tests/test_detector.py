import unittest
from datetime import datetime, timedelta, timezone
import uuid
import sys
import os

# Allow importing from the parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detector import detect_brute_force, THRESHOLD, TIME_WINDOW_MINS

class TestDetector(unittest.TestCase):
    
    def generate_test_logs(self, ip, count, status="FAILED", time_spread_mins=1):
        """Helper to generate mock logs spread over a specific time window."""
        logs = []
        base_time = datetime.now(timezone.utc)
        for i in range(count):
            # Spread logs evenly over the requested minutes
            offset = timedelta(minutes=(i / count) * time_spread_mins)
            logs.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": (base_time + offset).isoformat(),
                "event_type": "authentication",
                "username": "testuser",
                "source_ip": ip,
                "login_status": status
            })
        return logs

    def test_brute_force_detected(self):
        """Test that reaching the threshold within the time window triggers an alert."""
        # 10 failed logins in 1 minute -> SHOULD trigger
        logs = self.generate_test_logs("10.0.0.1", THRESHOLD, "FAILED", 1)
        alerts = detect_brute_force(logs)
        self.assertEqual(len(alerts), 1)

    def test_time_window_enforced(self):
        """Test that failures spread out too slowly do NOT trigger an alert."""
        # 10 failed logins spread over 5 minutes (threshold is 2 mins) -> SHOULD NOT trigger
        logs = self.generate_test_logs("10.0.0.2", THRESHOLD, "FAILED", TIME_WINDOW_MINS + 3)
        alerts = detect_brute_force(logs)
        self.assertEqual(len(alerts), 0)

    def test_success_logins_ignored(self):
        """Test that successful logins do not count towards the threshold."""
        # 10 SUCCESS logins in 1 minute -> SHOULD NOT trigger
        logs = self.generate_test_logs("10.0.0.3", THRESHOLD, "SUCCESS", 1)
        alerts = detect_brute_force(logs)
        self.assertEqual(len(alerts), 0)

    def test_invalid_log_data(self):
        """Test that missing data properly raises a KeyError."""
        logs = [{"invalid": "data"}]
        with self.assertRaises(KeyError):
            detect_brute_force(logs)

if __name__ == '__main__':
    unittest.main()
