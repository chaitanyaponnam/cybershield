
import random
from datetime import datetime, timedelta
from uuid import uuid4


class LogGenerator:

    @staticmethod
    def generate_logs():
        events = []
        now = datetime.now()

        # Simulated normal login activity
        for i in range(20):
            events.append({
                "event_id": str(uuid4()),
                "ip": f"192.168.1.{random.randint(20, 50)}",
                "username": f"user{i}",
                "status": random.choice(
                    ["SUCCESS", "SUCCESS", "FAILED"]
                ),
                "timestamp": (
                    now + timedelta(seconds=i * 30)
                ).isoformat()
            })

        # Simulated brute-force activity
        for i in range(8):
            events.append({
                "event_id": str(uuid4()),
                "ip": "10.0.0.99",
                "username": "admin",
                "status": "FAILED",
                "timestamp": (
                    now + timedelta(seconds=i * 10)
                ).isoformat()
            })

        return events