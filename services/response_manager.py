
from datetime import datetime, timezone
from uuid import uuid4


class ResponseManager:
    """Manage simulated SOC incident response actions."""

    VALID_ACTIONS = {
        "ACKNOWLEDGE",
        "ESCALATE",
        "CONTAIN",
        "RESOLVE",
    }

    def __init__(self):
        self._history = []

    def record_action(
        self,
        incident_id,
        action,
        performed_by="SOC Analyst",
        details=""
    ):
        """Validate and record a simulated response action."""

        if not isinstance(incident_id, str) or not incident_id.strip():
            raise ValueError("Incident ID must not be empty.")

        if not isinstance(action, str):
            raise ValueError("Action must be a string.")

        action = action.strip().upper()

        if action not in self.VALID_ACTIONS:
            raise ValueError(f"Invalid response action: {action}")

        if not isinstance(performed_by, str) or not performed_by.strip():
            raise ValueError("Performed-by value must not be empty.")

        if not isinstance(details, str):
            raise ValueError("Details must be a string.")

        record = {
            "action_id": str(uuid4()),
            "incident_id": incident_id.strip(),
            "action": action,
            "performed_by": performed_by.strip(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details.strip(),
        }

        self._history.append(record)
        return record.copy()

    def get_history(self, incident_id=None):
        """Return response history, optionally for one incident."""

        if incident_id is None:
            records = self._history
        else:
            if not isinstance(incident_id, str) or not incident_id.strip():
                raise ValueError("Incident ID must not be empty.")
            records = [
                record
                for record in self._history
                if record["incident_id"] == incident_id.strip()
            ]

        return [record.copy() for record in records]

    def get_action_count(self, incident_id=None):
        """Return the number of recorded response actions."""

        return len(self.get_history(incident_id))
