from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "readiness_inventory.sh"


def test_readiness_inventory_uses_only_read_commands() -> None:
    text = SCRIPT.read_text(encoding="utf-8").lower()

    forbidden = [
        "az role assignment create",
        "az role assignment delete",
        "az containerapp create",
        "az containerapp update",
        "az containerapp delete",
        "az group create",
        "az group delete",
        "az keyvault secret",
        "az storage account keys",
        "az storage account show-connection-string",
        "--show-values",
        "client-secret",
        "credential reset",
    ]

    for phrase in forbidden:
        assert phrase not in text


def test_readiness_inventory_contains_expected_inventory_queries() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    expected = [
        "az account show --output json",
        "az account list --output json",
        "az group list --output json",
        "az containerapp env list --output json",
        "az containerapp list --output json",
    ]
    for command in expected:
        assert command in text
