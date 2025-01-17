from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import random

valid_phone_numbers = {str(i) * 9 for i in range(10)} # phone number is of pattern "ddddddddd" e.g. "111111111"

def validate_client_id(client_id):
    return client_id in valid_phone_numbers

def generate_otc():
    return ''.join(random.choices('0123456789', k=6))

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(signature, message, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except InvalidSignature:
        return False
    
def sign(private_key, message):
    return private_key.sign(message, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

def encrypt(public_key, message):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

def decrypt(pri_key, enc_message):
    return pri_key.decrypt(enc_message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(),
                                                     label=None
                                                     ))