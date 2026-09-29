
from core.security_engine import SecurityEngine
from core.incident_manager import IncidentManager


engine = SecurityEngine()

alerts = engine.run_scan()

manager = IncidentManager()

incidents = manager.correlate(alerts)

print("\n===== CORRELATED INCIDENTS =====")

for incident in incidents:
    incident.display()

manager.save_incidents()

print(f"\nTotal Alerts: {len(alerts)}")
print(f"Total Incidents: {len(incidents)}")