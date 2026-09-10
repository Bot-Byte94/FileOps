from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

PRIVATE_KEY_FILE = "fileops_private.pem"
PUBLIC_KEY_FILE = "fileops_public.pem"

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

private_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

public_pem = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open(PRIVATE_KEY_FILE, "wb") as f:
    f.write(private_pem)

with open(PUBLIC_KEY_FILE, "wb") as f:
    f.write(public_pem)

print("Wrote:", PRIVATE_KEY_FILE)
print("Wrote:", PUBLIC_KEY_FILE)
print("\nIMPORTANT: never ship fileops_private.pem. Embed fileops_public.pem in fileops.py.")
