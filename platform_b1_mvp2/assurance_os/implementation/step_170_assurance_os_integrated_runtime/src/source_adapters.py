import json
from pathlib import Path


APPROVED_PREDECESSOR_ROOTS = (
    "platform_b1_mvp2/assurance_os/implementation/step_160_aurora17_qc_batch_release_slice",
    "platform_b1_mvp2/assurance_os/implementation/step_162_first_tier_triad_shared_assurance_kernel",
    "platform_b1_mvp2/assurance_os/implementation/step_164_first_tier_triad_assurance_orchestrator_api",
    "platform_b1_mvp2/assurance_os/implementation/step_166_first_tier_triad_commercial_demonstration_console",
)


def load_fixture(runtime_root, track_id):
    path = (
        Path(runtime_root) /
        "data" /
        "fixtures" /
        (track_id + "_fixture.json")
    )

    return json.loads(
        path.read_text(encoding="utf-8")
    )


def load_scenario_catalog(runtime_root):
    path = (
        Path(runtime_root) /
        "config" /
        "scenario_catalog.json"
    )

    return json.loads(
        path.read_text(encoding="utf-8")
    )


def load_predecessor_json(repo_root, relative_path):
    normalized = relative_path.replace("\\", "/")

    if not any(
        normalized.startswith(root + "/")
        for root in APPROVED_PREDECESSOR_ROOTS
    ):
        raise ValueError(
            "Path is outside approved read-only predecessor roots."
        )

    repository = Path(repo_root).resolve()
    target = (repository / normalized).resolve()

    if repository not in target.parents:
        raise ValueError(
            "Resolved predecessor path escapes the repository."
        )

    return json.loads(
        target.read_text(encoding="utf-8")
    )
