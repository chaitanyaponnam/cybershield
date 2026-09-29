
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from services.file_manager import FileManager
from services.log_history import LogHistory


class TestLogHistory(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.original_data_dir = FileManager.DATA_DIR

        FileManager.DATA_DIR = Path(
            self.temp_dir.name
        )

    def tearDown(self):
        FileManager.DATA_DIR = (
            self.original_data_dir
        )

        self.temp_dir.cleanup()

    @staticmethod
    def make_event(event_id):
        return {
            "event_id": event_id,
            "ip": "10.0.0.99",
            "username": "admin",
            "status": "FAILED",
            "timestamp": "2026-09-29T10:00:00"
        }

    def test_empty_history(self):
        self.assertEqual(
            LogHistory.load_events(),
            []
        )

    def test_append_new_events(self):
        result = LogHistory.append_events([
            self.make_event("A"),
            self.make_event("B")
        ])

        self.assertEqual(result["added"], 2)
        self.assertEqual(result["total"], 2)

        self.assertEqual(
            len(LogHistory.load_events()),
            2
        )

    def test_duplicate_batch_is_not_saved_twice(self):
        batch = [
            self.make_event("A"),
            self.make_event("B")
        ]

        LogHistory.append_events(batch)

        result = LogHistory.append_events(batch)

        self.assertEqual(result["added"], 0)
        self.assertEqual(result["total"], 2)

    def test_duplicate_ids_within_batch(self):
        result = LogHistory.append_events([
            self.make_event("A"),
            self.make_event("A"),
            self.make_event("B")
        ])

        self.assertEqual(result["added"], 2)
        self.assertEqual(result["total"], 2)

    def test_preserves_legacy_events(self):
        legacy_event = {
            "ip": "192.168.1.20",
            "username": "old_user",
            "status": "FAILED",
            "timestamp": "2026-09-01T10:00:00"
        }

        FileManager.save_data(
            "login_logs.json",
            [legacy_event]
        )

        LogHistory.append_events([
            self.make_event("NEW")
        ])

        events = LogHistory.load_events()

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0], legacy_event)

    def test_generate_and_save(self):
        generated = [
            self.make_event("A"),
            self.make_event("B")
        ]

        with patch(
            "services.log_history."
            "LogGenerator.generate_logs",
            return_value=generated
        ):
            result = (
                LogHistory.generate_and_save()
            )

        self.assertEqual(
            result["generated"],
            2
        )

        self.assertEqual(
            result["added"],
            2
        )

        self.assertEqual(
            result["total"],
            2
        )


if __name__ == "__main__":
    unittest.main()