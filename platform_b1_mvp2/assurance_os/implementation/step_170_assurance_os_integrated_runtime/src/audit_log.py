import json
from pathlib import Path

from .canonicalization import sha256_json


def append_event(events, event):
    previous_hash = (
        events[-1]["event_sha256"]
        if events
        else "GENESIS"
    )

    record = dict(event)
    record["previous_event_sha256"] = (
        previous_hash
    )
    record["event_sha256"] = (
        sha256_json(record)
    )

    events.append(record)
    return record


def verify_chain(events):
    previous_hash = "GENESIS"

    for event in events:
        candidate = dict(event)
        event_hash = candidate.pop(
            "event_sha256",
            None,
        )

        if (
            candidate.get(
                "previous_event_sha256"
            ) != previous_hash
        ):
            return False

        if sha256_json(candidate) != event_hash:
            return False

        previous_hash = event_hash

    return True


def write_jsonl(path, events):
    target = Path(path)
    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    lines = [
        json.dumps(
            event,
            sort_keys=True,
        )
        for event in events
    ]

    with target.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as stream:
        stream.write("\n".join(lines) + "\n")
