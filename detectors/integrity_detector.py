
import hashlib
from pathlib import Path

from core.detector import ThreatDetector
from core.alert import Alert
from services.file_manager import FileManager


class IntegrityDetector(ThreatDetector):

    def __init__(self):
        super().__init__("File Integrity Monitor")
        self.baseline_file = "file_hashes.json"

    def calculate_hash(self, file_path):
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            for chunk in iter(
                lambda: file.read(4096), b""
            ):
                sha256.update(chunk)

        return sha256.hexdigest()

    def create_baseline(self, file_paths):
        baseline = {}

        for file_path in file_paths:
            path = Path(file_path).resolve()

            if not path.is_file():
                print(f"File not found: {path}")
                continue

            baseline[str(path)] = self.calculate_hash(path)

        FileManager.save_data(
            self.baseline_file,
            baseline
        )

        print("Integrity baseline created.")

    def detect(self, events):
        if not self._enabled:
            return []

        baseline = FileManager.load_data(
            self.baseline_file
        )

        if not isinstance(baseline, dict) or not baseline:
            print("No baseline found. Create one first.")
            return []

        alerts = []

        for file_path in events:
            path = Path(file_path).resolve()
            saved_hash = baseline.get(str(path))

            if saved_hash is None:
                print(f"File not in baseline: {path.name}")
                continue

            if not path.is_file():
                description = f"Monitored file missing: {path.name}"

            elif self.calculate_hash(path) != saved_hash:
                description = f"File modified: {path.name}"

            else:
                print(f"Integrity verified: {path.name}")
                continue

            alerts.append(
                Alert(
                    "File Integrity Violation",
                    "HIGH",
                    "LOCAL_FILE",
                    description,
                    affected_file=path.name
                )
            )

        return alerts