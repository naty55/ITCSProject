from dataclasses import dataclass

@dataclass
class Message:
    from_peer_id: str
    to_peer_id: str
    content: str

    def __str__(self):
        return f"{self.from_peer_id}: {self.content}"
