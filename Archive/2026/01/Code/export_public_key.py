from cryptography.hazmat.primitives import serialization

PRIVATE_KEY_PATH = "fileops_private_key.pem"
OUT_PUBLIC_KEY_PATH = "fileops_public_key.pem"

with open(PRIVATE_KEY_PATH, "rb") as f:
    priv = serialization.load_pem_private_key(f.read(), password=None)

pub_pem = priv.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open(OUT_PUBLIC_KEY_PATH, "wb") as f:
    f.write(pub_pem)

print("Wrote:", OUT_PUBLIC_KEY_PATH)
print(pub_pem.decode("utf-8"))
