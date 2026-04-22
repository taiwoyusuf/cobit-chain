from azure.storage.blob import BlobServiceClient
import requests
import hashlib

file_url = "https://cobitchainstorage01.blob.core.windows.net/cobitchain-evidence/audit_file_v1.txt?sp=r&st=2026-03-28T13:34:56Z&se=2026-03-28T21:49:56Z&spr=https&sv=2024-11-04&sr=b&sig=2j%2FJWScghuHJWoA7PPosohb5ig2ceWaHuyLSvRblyW8%3D"
expected_hash = "dd8e56f28aa32e073e5417c5e8ff7ae1d04f14a688e91efd830c9e518219863b"

response = requests.get(file_url)
file_bytes = response.content

current_hash = hashlib.sha256(file_bytes).hexdigest()

print("Expected Hash:", expected_hash)
print("Current  Hash:", current_hash)

if current_hash == expected_hash:
    print("✅ VERIFIED: File is authentic (NO TAMPER)")
else:
    print("❌ ALERT: File has been modified (TAMPER DETECTED)")
