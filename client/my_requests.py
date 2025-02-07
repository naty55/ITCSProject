import time 

def register(client_id:str, public_key: bytes):
    return b'register ' + client_id.encode() + b'\n\n' + public_key

def verify_otc(otc: bytes, encryptor, signer):
    return b'verify_otc\n\n' + encryptor(otc) + signer(otc)

def connect(peer_id: str, signer):
    id_bytes = f"{peer_id}-hello-{time.time()}".encode()
    return b'connect ' + id_bytes + b'\n\n' + signer(id_bytes)

def public_key(peer_id: str, signer):
    req = f'get_public_key {peer_id} {time.time()}'.encode()
    return req + b'\n\n' + signer(req)

def get_messages():
    return b'get_messages\n\n'