from enum import Enum
import utils
import os
from message import Message
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding



class PeerStatus(Enum):
    """
    Peer shared key status
    """
    UNKOWN = 0  
    ASK = 1
    KNOWN = 2

class Peer:
    def __init__(self, peer_id):
        self.id = peer_id
        self.shared_key = None
        self.status = PeerStatus.UNKOWN
        self.public_key = None
        self.messages = []
        self.id_to_message = dict()
        self.next_message_no = 0
    
    def is_known(self):
        return self.public_key is not None
    
    def set_public_key(self, public_key):
        self.public_key = public_key
    
    def set_shared_key(self, shared_key):
        if shared_key:
            self.status = PeerStatus.KNOWN
            self.shared_key = shared_key

    
    def generate_shared_key(self):
        if not self.is_known():
            raise Exception("Can't generate shared key without public key")
        self.set_shared_key(os.urandom(32))
        return utils.encrypt(self.public_key, self.shared_key)
    
    def get_next_message_no(self):
        self.next_message_no += 1
        return self.next_message_no
    
    def accept_message(self, peer_id, message, _from=True):
        from_peer_id = peer_id if _from else self.id
        to_peer_id = self.id if _from else peer_id
        timestamp = datetime.now().isoformat()
        self.messages.append(Message(from_peer_id, to_peer_id, message, "-1", timestamp))
    
    def message_sent(self, message: Message) -> None:
        self.messages.append(message)
        self.id_to_message[message.msg_id] = message

    
    def aes_encrypt(self, plaintext) -> bytes:
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(bytes(plaintext, 'utf-8')) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext
    
    def aes_decrypt(self, iv_ciphertext) -> bytes:
        iv = iv_ciphertext[:16]
        ciphertext = iv_ciphertext[16:]

        cipher = Cipher(algorithms.AES(self.shared_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
    
    def __str__(self):
        return f"Peer {self.id} - {self.status} - {self.shared_key}"
    

