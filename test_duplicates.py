
from core.security_engine import SecurityEngine
from core.incident_manager import IncidentManager


engine = SecurityEngine()
manager = IncidentManager()

print("\n===== FIRST SCAN =====")

alerts = engine.run_scan()
manager.correlate(alerts)
manager.save_incidents()

for incident in manager.incidents.values():
    print(
        incident.title,
        "Alerts:",
        len(incident.alerts)
    )

print("\n===== SECOND SCAN =====")

alerts = engine.run_scan()
manager.correlate(alerts)
manager.save_incidents()

for incident in manager.incidents.values():
    print(
        incident.title,
        "Alerts:",
        len(incident.alerts)
    )