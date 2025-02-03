from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from socket import socket
from threading import Lock
import utils
from time import time

@dataclass
class Client:
    client_id: str
    public_key: RSAPublicKey
    conn: socket
    conn_lock: Lock
    has_session: bool
    incoming_messages: list[bytes]
    otc: str = None
    otc_timestamp: float = None
    
    MAX_TIME_TO_VERIFY_OTC = 30

    def verify_otc(self, recieved_ots: bytes):
        """
        Verify OTC matches and it's recieved in the correct time window (under 30 seconds from sending)
        """
        return  recieved_ots.decode() == self.otc and time() - self.otc_timestamp < Client.MAX_TIME_TO_VERIFY_OTC

    def verify_signature(self, message: bytes, signature: bytes):
        return utils.verify_signature(self.public_key, message, signature)
    
    def get_public_key_bytes(self):
        return utils.serialize_public_key(self.public_key)
    
    def recv_message(self, message: bytes):
        if self.has_session:
            with self.conn_lock:
                self.conn.send(message)
        else:
            if len(self.incoming_messages) >= 10:
                return False
            self.incoming_messages.append(message)
        return True
    
    def disconnect(self):
        print(f"client {self.client_id} has been disconnected")
        self.conn.close()
        self.has_session = False
        self.conn = None
        self.otc = None
        self.otc_timestamp = None