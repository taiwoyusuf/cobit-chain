import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
EVALUATOR_DIR = REPO_ROOT / "platform_b1_mvp2" / "evaluators"
MOCK_DATA_DIR = REPO_ROOT / "platform_b1_mvp2" / "mock_data"

sys.path.insert(0, str(EVALUATOR_DIR))

from workflow_dependency_evaluator import evaluate_file


def main() -> int:
    mock_path = MOCK_DATA_DIR / "prakriti_middleware_verified_lis_held.json"
    result = evaluate_file(mock_path)

    print(json.dumps(result, indent=2))

    required_terms = [
        "Workflow Dependency Assurance Lens",
        "WORKFLOW APPEARS COMPLETE BUT BLOCKED",
        "LIS HOLD DETECTED",
        "MANDATORY FIELD MISSING",
        "SECONDARY REVIEW REQUIRED",
        "RESULT RELEASE NOT ADMISSIBLE",
    ]

    rendered = json.dumps(result)

    missing = [term for term in required_terms if term not in rendered]
    if missing:
        print("STOP: Missing required evaluator outputs:")
        for item in missing:
            print(f"- {item}")
        return 1

    print("PASS: Workflow Dependency Assurance evaluator smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
