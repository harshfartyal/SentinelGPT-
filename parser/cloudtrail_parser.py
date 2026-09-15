import json
from pathlib import Path


def load_cloudtrail_logs(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)

    return data["Records"]


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    log_file = project_root / "data" / "sample_cloudtrail.json"

    logs = load_cloudtrail_logs(log_file)

    print("CloudTrail logs loaded successfully!")
    print("Total events:", len(logs))

    for log in logs:
        print(
            log["eventTime"],
            "|",
            log["eventName"],
            "|",
            log["sourceIPAddress"]
        )