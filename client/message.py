from dataclasses import dataclass

@dataclass
class Message:
    from_peer_id: str
    to_peer_id: str
    content: str
    msg_id: str
    timestamp: str
    msg_status: str = "S"

    def __str__(self):
        return f"{self.from_peer_id} - {self.msg_id} - {self.msg_status} - {self.timestamp}: {self.content}"
    
    def message_received(self):
        self.msg_status = "R"
    
    def to_bytes(self, encryptor, signer = None):
        hmac = signer(self.content)
        return f"message {self.to_peer_id} {self.msg_id}\n\nMSG".encode() + encryptor(self.content) + hmac
    
    @staticmethod
    def from_bytes(header: bytes, data: bytes, to_peer_id: str, timestamp: str, decryptor, signer=None):
        from_peer_id, msg_id = header.split(b' ')
        content, signature = data[:-32], data[-32:]
        message =  Message(from_peer_id.decode(), to_peer_id, decryptor(content).decode(), msg_id.decode(), timestamp, msg_status="R")
        calc_signature = signer(message.content)
        if calc_signature != signature:
            raise Exception(f"Couldn't verify HMAC signature for message {message.msg_id} from {message.from_peer_id} to {message.to_peer_id}")
        return message
    
    @staticmethod
    def ack_message_bytes(msg_id: str, peer_id: str, signer):
        return f"message {peer_id} {msg_id}\n\nACK".encode() + signer(f"{peer_id} {msg_id}")
    
    @staticmethod
    def syn_message_bytes(peer_id, shared_key_generator):
        shared_key_encrypted = shared_key_generator() 
        return f"message {peer_id} \n\nSYN".encode() + shared_key_encrypted
