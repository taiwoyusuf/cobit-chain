def evaluate_dependencies(dependencies):
    failures = []
    evaluated = []

    for dependency in dependencies:
        required = bool(
            dependency.get("required", True)
        )

        checks = {
            "present": bool(
                dependency.get("present", False)
            ),
            "current": bool(
                dependency.get("current", False)
            ),
            "agrees": bool(
                dependency.get("agrees", False)
            ),
        }

        passed = (
            not required or
            all(checks.values())
        )

        evaluated.append({
            "name": dependency.get(
                "name",
                "UNNAMED_DEPENDENCY",
            ),
            "required": required,
            "checks": checks,
            "passed": passed,
        })

        if not passed:
            failures.append(
                dependency.get(
                    "name",
                    "UNNAMED_DEPENDENCY",
                )
            )

    valid = not failures

    return {
        "state": (
            "DEPENDENCIES_VERIFIED"
            if valid
            else "DEPENDENCY_FAILURE"
        ),
        "valid": valid,
        "failures": failures,
        "evaluated": evaluated,
        "fail_closed": not valid,
    }
