import json
import os


HISTORY_FILE = "reports/history.json"


def load_history():

    if not os.path.exists(
        HISTORY_FILE
    ):
        return []

    try:

        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (json.JSONDecodeError, OSError):

        return []


def save_history(scan):

    os.makedirs(
        "reports",
        exist_ok=True
    )

    history = load_history()

    history.append(scan)

    with open(
        HISTORY_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            history,
            file,
            indent=4
        )


def compare_last_scan(current):

    history = load_history()

    if not history:
        return {
            "new_ports": [],
            "closed_ports": []
        }

    previous = history[-1]

    old_ports = {
        item["port"]
        for item in previous.get(
            "open_ports",
            []
        )
    }

    new_ports = {
        item["port"]
        for item in current.get(
            "open_ports",
            []
        )
    }

    return {
        "new_ports": sorted(
            new_ports - old_ports
        ),
        "closed_ports": sorted(
            old_ports - new_ports
        )
    }