import socket
import os 
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import importlib.resources 
import resources

class Client:
    def __init__(self, client_id):
        self.id = client_id
        self.private_key = Client.load_private_key()
        self.public_key = self.private_key.public_key()
        self.server_public_key = Client.load_server_public_key()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = self.socket.connect(("localhost", 6789))
        self.peers = dict()
        print(self.server_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
        print(self.private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))

        
    def register(self):
        public_key_bytes = self.get_public_key_bytes()
        print(f"len of public bytes {len(public_key_bytes)}")
        reg_request = b'register ' + bytes(self.id, 'utf-8') + b'\n\n' + public_key_bytes
        self.socket.send(reg_request)

        otc = self.socket.recv(6)
        print(f"Got OTC over \"secured\" channel {otc}")

        verify_otc_req = b'verify_otc ' + otc + b'\n\n'
        signature = self.private_key.sign(otc, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
            )
        verify_otc_req += signature
        self.socket.send(verify_otc_req)
    
    def send_message(self, peer_id, message):
        pass

    def load_private_key():
        if importlib.resources.is_resource(resources, "private.pem"):
            return serialization.load_pem_private_key(
                importlib.resources.read_binary(resources, "private.pem"), password=None)
        
        private = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        private_pem = private.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption()
                                            )
        with open(os.path.dirname(__file__) + "/resources/private.pem", "wb") as pri_file:
            pri_file.write(private_pem)
        return private
    
    def load_server_public_key():
        return serialization.load_pem_public_key(importlib.resources.read_binary(resources, "server.pem"))
    
    def get_public_key_bytes(self):
        return self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                

client = Client("111111111")
client.register()

