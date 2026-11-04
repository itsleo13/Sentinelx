import csv
import json
import os
from datetime import datetime


REPORT_DIR = "reports"


def ensure_report_dir():
    os.makedirs(
        REPORT_DIR,
        exist_ok=True
    )


def save_json(data):
    ensure_report_dir()

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    path = os.path.join(
        REPORT_DIR,
        f"sentinelx_{timestamp}.json"
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            data,
            file,
            indent=4
        )

    return path


def save_csv(open_ports):
    ensure_report_dir()

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    path = os.path.join(
        REPORT_DIR,
        f"sentinelx_{timestamp}.csv"
    )

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "Port",
            "Protocol",
            "Service",
            "Banner"
        ])

        for item in open_ports:

            writer.writerow([
                item["port"],
                item["protocol"],
                item["service"],
                item.get("banner")
            ])

    return path
    