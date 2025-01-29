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
        return f"{self.from_peer_id} - {self.msg_id} - {'V' * (2 if self.msg_status == 'R' else 1)} - {self.timestamp}: {self.content}"
    
    def message_received(self):
        self.msg_status = "R"
    
    def to_bytes(self, encryptor):
        return f"message {self.to_peer_id} {self.msg_id}\n\nMSG".encode() + encryptor(self.content)
    
    @staticmethod
    def from_bytes(data, to_peer_id, timestamp, decryptor):
        from_peer_id, msg_id, content = data.split(b' ')
        return Message(from_peer_id.decode(), to_peer_id, msg_id.decode(), decryptor(content).decode(), timestamp, msg_status="R")
