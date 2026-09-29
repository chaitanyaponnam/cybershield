
from core.incident_manager import IncidentManager


manager = IncidentManager()

print("===== SAVED INCIDENTS =====")

for incident in manager.incidents.values():
    incident.display()

print("\n===== UPDATE INCIDENT =====")

incidents = list(manager.incidents.values())

if incidents:
    selected = incidents[0]

    manager.update_incident(
        selected.incident_id,
        "INVESTIGATING"
    )

    print("Incident status updated.")

print("\n===== RELOAD INCIDENTS =====")

new_manager = IncidentManager()

for incident in new_manager.incidents.values():
    incident.display()