
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


class EvidenceIntegrity:
    """Create and verify SHA-256 manifests for exported reports."""

    CHUNK_SIZE = 65536

    @classmethod
    def calculate_hash(cls, file_path):
        file_path = Path(file_path)
        sha256 = hashlib.sha256()

        with file_path.open("rb") as file:
            for chunk in iter(
                lambda: file.read(cls.CHUNK_SIZE),
                b""
            ):
                sha256.update(chunk)

        return sha256.hexdigest()

    @staticmethod
    def get_manifest_path(report_path):
        report_path = Path(report_path)
        return report_path.with_name(
            report_path.name + ".sha256.json"
        )

    @classmethod
    def create_manifest(cls, report_path):
        report_path = Path(report_path).resolve()

        if not report_path.is_file():
            raise FileNotFoundError(
                f"Report not found: {report_path}"
            )

        manifest_path = cls.get_manifest_path(report_path)

        manifest = {
            "manifest_version": 1,
            "algorithm": "SHA-256",
            "report_filename": report_path.name,
            "report_size": report_path.stat().st_size,
            "sha256": cls.calculate_hash(report_path),
            "created_at": datetime.now(
                timezone.utc
            ).isoformat()
        }

        with manifest_path.open(
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(manifest, file, indent=4)

        return manifest_path

    @classmethod
    def verify_report(cls, report_path):
        report_path = Path(report_path).resolve()
        manifest_path = cls.get_manifest_path(report_path)

        if not manifest_path.is_file():
            return {
                "status": "MANIFEST_MISSING",
                "report": str(report_path)
            }

        try:
            with manifest_path.open(
                "r",
                encoding="utf-8"
            ) as file:
                manifest = json.load(file)
        except (OSError, ValueError):
            return {
                "status": "INVALID_MANIFEST",
                "report": str(report_path)
            }

        if not isinstance(manifest, dict):
            return {
                "status": "INVALID_MANIFEST",
                "report": str(report_path)
            }

        expected_hash = manifest.get("sha256")
        expected_name = manifest.get("report_filename")
        expected_size = manifest.get("report_size")

        valid_hash = (
            isinstance(expected_hash, str)
            and len(expected_hash) == 64
            and all(
                char in "0123456789abcdef"
                for char in expected_hash
            )
        )

        valid_metadata = (
            manifest.get("manifest_version") == 1
            and manifest.get("algorithm") == "SHA-256"
            and expected_name == report_path.name
            and isinstance(expected_size, int)
            and not isinstance(expected_size, bool)
            and expected_size >= 0
        )

        if not valid_hash or not valid_metadata:
            return {
                "status": "INVALID_MANIFEST",
                "report": str(report_path)
            }

        if not report_path.is_file():
            return {
                "status": "REPORT_MISSING",
                "report": str(report_path)
            }

        actual_hash = cls.calculate_hash(report_path)
        actual_size = report_path.stat().st_size

        if (
            actual_hash != expected_hash
            or actual_size != expected_size
        ):
            status = "MODIFIED"
        else:
            status = "VERIFIED"

        return {
            "status": status,
            "report": str(report_path),
            "expected_sha256": expected_hash,
            "actual_sha256": actual_hash,
            "expected_size": expected_size,
            "actual_size": actual_size
        }