from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization



private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public = private.public_key()

private_pem = private.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.PKCS8,
   encryption_algorithm=serialization.NoEncryption()
)

public_pem = public.public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("public.pem", "wb") as pub_file:
    pub_file.write(public_pem)

with open("private.pem", "wb") as pri_file:
    pri_file.write(private_pem)