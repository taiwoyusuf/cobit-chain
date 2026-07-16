"""Authorized track registry validation."""

from typing import Mapping, Sequence


AUTHORIZED_TRACKS = (
    "AURORA17",
    "IRLT",
    "COMPOUNDING",
    "DSCSA",
)


def validate_tracks(tracks: Sequence[Mapping[str, object]]) -> dict:
    codes = tuple(str(item.get("code")) for item in tracks)

    passed = (
        codes == AUTHORIZED_TRACKS
        and all(item.get("enabled") is True for item in tracks)
    )

    return {
        "passed": passed,
        "codes": list(codes),
    }


def select_track(tracks: Sequence[Mapping[str, object]], code: str) -> dict:
    if code not in AUTHORIZED_TRACKS:
        raise ValueError("Unauthorized track")

    for track in tracks:
        if track.get("code") == code and track.get("enabled") is True:
            return dict(track)

    raise ValueError("Authorized track is unavailable")
