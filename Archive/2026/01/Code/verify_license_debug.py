import json, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

FILEOPS_PUBLIC_KEY_PEM = b"""
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA252y+RV+fpOzhafaExR3
mEpI53wdDWxHW6xCS2grYHikfnjix+KTjI8qmEQTtOEbcu+Ua7TXUw5YWqfM26NG
oemGcgk4BI7OZcCG311phEU/A0tSD6uhWX0uROR88Z2u3cYYiXfbnrfODs1LCmxi
oKACfArBuPfwrmUn2WN/JE1VSKxnY6nsX4iMm05QIzydbtYqHtnFV2arDVN+MXdA
HmZzq9Gb45Ya2rKf95Kjf5rIDBN6Oa6L3Qdy8gGBKTt2tklN6LUCAJoSUGfa6nyU
xj6srTIm47hhUmlAbPx/v3ln6b+Sro8nmQAA8noY9Vl9kNxetv7T6AcMVR+kkyI3
nQIDAQAB
-----END PUBLIC KEY-----
"""

def canonical_payload_bytes(lic: dict) -> bytes:
    lic2 = dict(lic)
    lic2.pop("signature", None)
    return json.dumps(
        lic2,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

with open("fileops.license", "r", encoding="utf-8") as f:
    lic = json.load(f)

payload = canonical_payload_bytes(lic)
sig = base64.b64decode(lic["signature"])

pub = serialization.load_pem_public_key(FILEOPS_PUBLIC_KEY_PEM)

try:
    pub.verify(
        sig,
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    print("✅ SIGNATURE VALID (keypair matches)")
except InvalidSignature:
    print("❌ INVALID SIGNATURE (wrong private key)")
