from dataclasses import dataclass

@dataclass
class Request:
    header: bytes
    payload: bytes
    req_type: str
    header_fields: list[bytes]

    @staticmethod
    def from_bytes(request_bytes: bytes):
        header, payload = request_bytes.split(b'\n\n', 1)
        header_fields = header.split(b' ')
        print("Header fields", header_fields)
        return Request(header, payload, header_fields[0].decode(), header_fields[1:])
    
    def is_of_type(self, req_type: str):
        return self.req_type == req_type