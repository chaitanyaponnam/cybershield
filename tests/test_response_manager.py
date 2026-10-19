
import unittest

from services.response_manager import ResponseManager


class TestResponseManager(unittest.TestCase):

    def setUp(self):
        self.manager = ResponseManager()

    def test_record_valid_action(self):
        record = self.manager.record_action(
            "INC-001", "ACKNOWLEDGE"
        )

        self.assertEqual(record["incident_id"], "INC-001")
        self.assertEqual(record["action"], "ACKNOWLEDGE")
        self.assertTrue(record["action_id"])
        self.assertTrue(record["timestamp"])

    def test_action_is_normalized(self):
        record = self.manager.record_action(
            "INC-001", "  contain  "
        )

        self.assertEqual(record["action"], "CONTAIN")

    def test_all_supported_actions(self):
        for action in self.manager.VALID_ACTIONS:
            record = self.manager.record_action("INC-001", action)
            self.assertEqual(record["action"], action)

    def test_invalid_action_is_rejected(self):
        with self.assertRaises(ValueError):
            self.manager.record_action("INC-001", "DELETE")

    def test_empty_incident_id_is_rejected(self):
        with self.assertRaises(ValueError):
            self.manager.record_action("", "ACKNOWLEDGE")

    def test_invalid_analyst_is_rejected(self):
        with self.assertRaises(ValueError):
            self.manager.record_action(
                "INC-001", "ACKNOWLEDGE", performed_by=" "
            )

    def test_history_is_recorded(self):
        self.manager.record_action("INC-001", "ACKNOWLEDGE")
        self.manager.record_action("INC-001", "ESCALATE")

        self.assertEqual(self.manager.get_action_count(), 2)

    def test_history_can_be_filtered_by_incident(self):
        self.manager.record_action("INC-001", "ACKNOWLEDGE")
        self.manager.record_action("INC-002", "CONTAIN")

        history = self.manager.get_history("INC-001")

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["incident_id"], "INC-001")

    def test_returned_record_cannot_mutate_stored_record(self):
        record = self.manager.record_action(
            "INC-001", "ACKNOWLEDGE"
        )
        record["action"] = "TAMPERED"

        history = self.manager.get_history("INC-001")
        self.assertEqual(history[0]["action"], "ACKNOWLEDGE")

    def test_history_records_are_returned_as_copies(self):
        self.manager.record_action("INC-001", "CONTAIN")
        history = self.manager.get_history()
        history[0]["action"] = "TAMPERED"

        self.assertEqual(
            self.manager.get_history()[0]["action"], "CONTAIN"
        )

    def test_action_count_for_unknown_incident(self):
        self.assertEqual(
            self.manager.get_action_count("INC-999"), 0
        )

    def test_unique_action_ids(self):
        first = self.manager.record_action("INC-001", "ACKNOWLEDGE")
        second = self.manager.record_action("INC-001", "ESCALATE")

        self.assertNotEqual(first["action_id"], second["action_id"])


if __name__ == "__main__":
    unittest.main()
