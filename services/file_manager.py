
import json
from pathlib import Path


class FileManager:

    DATA_DIR = Path(__file__).resolve().parent.parent / "data"

    @classmethod
    def save_data(cls, filename, data):
        cls.DATA_DIR.mkdir(exist_ok=True)

        file_path = cls.DATA_DIR / filename

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

        print(f"Saved: {file_path}")

    @classmethod
    def load_data(cls, filename):
        file_path = cls.DATA_DIR / filename

        if not file_path.exists():
            return []

        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)