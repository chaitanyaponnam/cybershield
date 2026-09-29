
from core.security_engine import SecurityEngine


def main():
    engine = SecurityEngine()

    alerts = engine.run_scan()

    print("\n===== DETECTED THREATS =====")

    for alert in alerts:
        alert.display()


if __name__ == "__main__":
    main()