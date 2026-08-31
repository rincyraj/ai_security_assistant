import json
from pathlib import Path


LOG_FILE = Path("data/logs/security_logs.json")


def load_logs():
    with open(LOG_FILE, "r") as file:
        logs = json.load(file) # Convert JSON data to a Python object (list of dictionaries)

    return logs


if __name__ == "__main__":
    logs = load_logs()

    print(f"Total logs: {len(logs)}")

    for log in logs:
        print(log)