import hashlib
import json
from pathlib import Path


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_bytes(value):
    return canonical_json(value).encode("utf-8")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest().upper()


def sha256_json(value):
    return sha256_bytes(canonical_bytes(value))


def read_json(path):
    return json.loads(
        Path(path).read_text(encoding="utf-8")
    )


def write_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    text = json.dumps(
        value,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ) + "\n"

    with target.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as stream:
        stream.write(text)
