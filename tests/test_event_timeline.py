
import tempfile
import unittest
from pathlib import Path

from services.file_manager import FileManager
from services.event_timeline import EventTimeline


class TestEventTimeline(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_data_dir = FileManager.DATA_DIR
        FileManager.DATA_DIR = Path(
            self.temp_dir.name
        )

        FileManager.save_data(
            "login_logs.json",
            [
                {
                    "event_id": "A",
                    "ip": "10.0.0.99",
                    "username": "admin",
                    "status": "FAILED",
                    "timestamp": "2026-09-29T10:00:00"
                },
                {
                    "event_id": "B",
                    "ip": "192.168.1.20",
                    "username": "user1",
                    "status": "SUCCESS",
                    "timestamp": "2026-09-29T10:02:00"
                },
                {
                    "event_id": "C",
                    "ip": "10.0.0.99",
                    "username": "admin",
                    "status": "FAILED",
                    "timestamp": "2026-09-29T10:04:00"
                }
            ]
        )

    def tearDown(self):
        FileManager.DATA_DIR = (
            self.original_data_dir
        )
        self.temp_dir.cleanup()

    def test_all_events(self):
        events = EventTimeline.search()
        self.assertEqual(len(events), 3)

    def test_filter_by_ip(self):
        events = EventTimeline.search(
            source_ip="10.0.0.99"
        )

        self.assertEqual(len(events), 2)

    def test_filter_by_status(self):
        events = EventTimeline.search(
            status="SUCCESS"
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(
            events[0]["event_id"],
            "B"
        )

    def test_filter_by_time_range(self):
        events = EventTimeline.search(
            start_time="2026-09-29T10:01:00",
            end_time="2026-09-29T10:03:00"
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(
            events[0]["event_id"],
            "B"
        )

    def test_chronological_order(self):
        events = EventTimeline.search()

        self.assertEqual(
            [
                event["event_id"]
                for event in events
            ],
            ["A", "B", "C"]
        )

    def test_summary(self):
        events = EventTimeline.search()
        summary = EventTimeline.summarize(events)

        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["failed"], 2)
        self.assertEqual(summary["successful"], 1)
        self.assertEqual(
            summary["unique_source_ips"],
            2
        )

    def test_invalid_time_range(self):
        with self.assertRaises(ValueError):
            EventTimeline.search(
                start_time="invalid"
            )

    def test_history_is_not_modified(self):
        original = FileManager.load_data(
            "login_logs.json"
        )

        EventTimeline.search(
            status="FAILED"
        )

        after = FileManager.load_data(
            "login_logs.json"
        )

        self.assertEqual(original, after)


if __name__ == "__main__":
    unittest.main()