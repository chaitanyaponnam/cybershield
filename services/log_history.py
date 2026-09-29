
from services.file_manager import FileManager
from services.log_generator import LogGenerator


class LogHistory:
    FILENAME = "login_logs.json"

    @classmethod
    def load_events(cls):
        events = FileManager.load_data(cls.FILENAME)

        if not isinstance(events, list):
            raise ValueError(
                "Login history must contain a JSON list."
            )

        return events

    @classmethod
    def append_events(cls, new_events):
        """
        Preserve saved events and append only new ones.

        Events with matching event IDs are not added
        again. Legacy events without IDs are preserved.
        """
        existing_events = cls.load_events()

        known_ids = {
            event["event_id"]
            for event in existing_events
            if isinstance(event, dict)
            and event.get("event_id")
        }

        combined_events = list(existing_events)
        added_count = 0

        for event in new_events:
            if not isinstance(event, dict):
                raise ValueError(
                    "Every login event must be a dictionary."
                )

            event_id = event.get("event_id")

            if not event_id:
                raise ValueError(
                    "New login events must have event IDs."
                )

            if event_id in known_ids:
                continue

            combined_events.append(event)
            known_ids.add(event_id)
            added_count += 1

        if added_count:
            FileManager.save_data(
                cls.FILENAME,
                combined_events
            )

        return {
            "added": added_count,
            "total": len(combined_events)
        }

    @classmethod
    def generate_and_save(cls):
        new_events = LogGenerator.generate_logs()
        result = cls.append_events(new_events)

        result["generated"] = len(new_events)

        return result