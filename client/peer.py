from enum import Enum
import utils
import os
from message import Message
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding, hmac, hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class PeerStatus(Enum):
    """
    Peer shared key status
    """
    UNKOWN = 0  
    ASK = 1
    KNOWN = 2

class Peer:
    def __init__(self, peer_id):
        self.id :str = peer_id
        self.shared_key : bytes = None
        self.status :PeerStatus = PeerStatus.UNKOWN
        self.public_key : RSAPublicKey = None
        self.messages: list[Message] = []
        self.id_to_message: dict[str, Message] = dict()
        self.next_message_no: int = 0
    
    def is_known(self):
        return self.public_key is not None
    
    def set_public_key(self, public_key: RSAPublicKey):
        self.public_key = public_key
    
    def set_shared_key(self, shared_key: bytes):
        if shared_key:
            self.status = PeerStatus.KNOWN
            self.shared_key = shared_key

    
    def generate_shared_key(self, signer) -> bytes:
        if not self.is_known():
            raise Exception("Can't generate shared key without public key")
        self.set_shared_key(os.urandom(32))
        return utils.encrypt(self.public_key, self.shared_key) + signer(self.shared_key)
    
    def get_next_message_no(self):
        self.next_message_no += 1
        return self.next_message_no
    
    def message_received(self, message: Message):
        self.messages.append(message)
    
    def message_sent(self, message: Message) -> None:
        self.messages.append(message)
        self.id_to_message[message.msg_id] = message
    
    def ack_recieved(self, msg_id: str):
        if msg_id in self.id_to_message:
            self.id_to_message[msg_id].message_received()

    
    def aes_encrypt(self, plaintext: str) -> bytes:
        if not self.shared_key:
            raise Exception("No shared key")
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(bytes(plaintext, 'utf-8')) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext
    
    def aes_decrypt(self, iv_ciphertext: bytes) -> bytes:
        if not self.shared_key:
            raise Exception("No shared key")
        iv = iv_ciphertext[:16]
        ciphertext = iv_ciphertext[16:]

        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
    
    def generate_hmac(self, message: str):
        if not self.shared_key:
            raise Exception("No shared Key - can't generate HMAC signature")
        return utils.generate_hmac(self.shared_key, message)
    
    def verify_hmac(self, message: str, signature: bytes):
        if not self.shared_key:
            raise Exception("No shared Key - can't verify signature")
        return utils.verify_hmac(self.shared_key, message, signature)
    
    def __str__(self):
        return f"Peer {self.id} - {self.status} - {self.shared_key}"
    
    def __getstate__(self):
        state = self.__dict__.copy()
        if state['public_key']: # Replace RSAPublicKey object with bytes as it can't be pickled
            state['public_key'] = utils.serialize_public_key(self.public_key)
        return state
    
    def __setstate__(self, state):
        if state['public_key']:
            state['public_key'] = utils.load_public_key(state['public_key'])
        self.__dict__.update(state)
    

