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
