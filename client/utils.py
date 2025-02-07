from cryptography.hazmat.primitives import serialization,hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.backends import default_backend
import random
import os

valid_phone_numbers = {str(i) * 9 for i in range(10)} # phone number is of pattern "ddddddddd" e.g. "111111111"

def validate_client_id(client_id: str):
    return client_id in valid_phone_numbers and client_id != os.environ['client_id'].strip()

def generate_otc():
    return ''.join(random.choices('0123456789', k=6))

def verify_signature(public_key: RSAPublicKey, message: bytes, signature: bytes):
    try:
        public_key.verify(signature, message, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except InvalidSignature:
        return False
    
def sign(private_key: RSAPrivateKey, message: bytes):
    return private_key.sign(message, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

def encrypt(public_key: RSAPublicKey, message: bytes):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

def decrypt(pri_key: RSAPrivateKey, enc_message: bytes):
    return pri_key.decrypt(enc_message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(),
                                                     label=None
                                                     ))

def serialize_public_key(public_key: RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(public_key: bytes) -> RSAPublicKey:
    return serialization.load_pem_public_key(public_key)

def load_private_key(private_key: bytes) -> RSAPrivateKey:
    return serialization.load_pem_private_key(private_key, password=None)

def serialize_private_key(private_key: RSAPrivateKey):
    return private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.PKCS8,
                                encryption_algorithm=serialization.NoEncryption())


def generate_hmac(shared_key: bytes, message: str) -> bytes:
    h = hmac.HMAC(shared_key, hashes.SHA256(), backend=default_backend())
    h.update(message.encode())
    return h.finalize()

def verify_hmac(shared_key: bytes, message: str, signature: bytes) -> bool:
    h = generate_hmac(shared_key, message)
    return h == signature
    