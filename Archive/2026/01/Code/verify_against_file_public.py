import json, base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def canonical_payload_bytes(lic: dict) -> bytes:
    lic2 = dict(lic)
    lic2.pop("signature", None)
    return json.dumps(lic2, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

lic = json.load(open("fileops.license", "r", encoding="utf-8"))
pub_pem = open("fileops_public.pem", "rb").read()

pub = serialization.load_pem_public_key(pub_pem)
payload = canonical_payload_bytes(lic)
sig = base64.b64decode(lic["signature"], validate=True)

try:
    pub.verify(sig, payload,
               padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
               hashes.SHA256())
    print("✅ License matches fileops_public.pem")
except InvalidSignature:
    print("❌ License does NOT match fileops_public.pem")
