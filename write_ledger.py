import requests
import hashlib

file_url = "https://cobitchainstorage01.blob.core.windows.net/cobitchain-evidence/test_evidence_v2.txt?sp=r&st=2026-03-28T10:56:02Z&se=2026-03-28T19:11:02Z&spr=https&sv=2024-11-04&sr=b&sig=ChuTbkKClvhOxKQ%2BUUispXLzYgBU%2FNdgjg4QyfKgDL4%3D"

expected_hash = "80bff7e8b91dd16ed305a77867a777b67aadb977a70de067e91b9b20f521b257"

r = requests.get(file_url)
current_hash = hashlib.sha256(r.content).hexdigest()

print("Expected Hash:", expected_hash)
print("Current  Hash:", current_hash)

if current_hash == expected_hash:
    print("✅ VERIFIED: File has NOT been tampered with")
else:
    print("❌ ALERT: File has been modified (TAMPER DETECTED)")
