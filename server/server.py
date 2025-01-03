import socket
from threading import Thread
from config import SERVER_HOST, SERVER_PORT
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
import resources
import utils
from importlib.resources import read_binary

class Server:
    def __init__(self):
        self.socket = None
        self.pri_key = Server.read_private_key()
        self.pub_key = self.pri_key.public_key()
        self.registered_clients = dict()
    
    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((SERVER_HOST, SERVER_PORT))
            s.listen(10)
            while True:
                conn, addr = s.accept()
                print(f"Accepted connection from {addr}")
                Thread(target=self.handle_new_connection, args=(conn,)).start()
    
    def handle_new_connection(self, conn):
        client = None
        data = conn.recv(4096)
        print(data)
        header, payload = data.split(b'\n\n', 1)
        req_type, client_id = header.split(b' ')
        client_id = client_id.decode()
        if req_type == b'register':
            if not self.handle_register_request(conn, client_id, payload):
                conn.close()
                return
            client = self.registered_clients[client_id]
        elif req_type == b'connect':
            signed_text_message = client_id
            client_id = client_id.split('-', 1)[0]
            if client_id not in self.registered_clients:
                print(f"Client id {client_id} is not registered user - connection denied")
                conn.close()
                return

            client = self.registered_clients[client_id]
            if client['has_session']:
                print(f"Client id {client_id} already has another session - connection denied")
                conn.close()
                return

            if not utils.verify_signature(client['public_key'], bytes(signed_text_message, "utf-8"), payload):
                print(f"Client id {client_id} couldn't be verified - connection denied")
                conn.close()
                return

            print(f"{client_id} has been successfully connected")
            client['has_session'] = True
        
        # Connection stays open for next requests
        while True:
            data = conn.recv(4096)
            if not data:
                client['has_session'] = False
                break
            self.handle_message_request(data)
        
    def handle_register_request(self, conn, client_id, payload):
        if not utils.validate_client_id(client_id):
            return False
        print(f"Client {client_id} is trying to register")
        
        if client_id in self.registered_clients:
            return False
        
        new_client = dict()
        new_client['public_key'] = serialization.load_pem_public_key(payload)
        self.send_by_secure_channel(client_id, conn, new_client)
        data = conn.recv(4096)
        
        header, payload = data.split(b'\n\n', 1)
        req_type = header
        otc_enc, signature = payload[:256], payload[256:]
        otc = self.pri_key.decrypt(otc_enc, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
        )
        
        if req_type != b'verify_otc':
            return False
        print(f"Recieved otc from client, client id {client_id}, otc={otc}")

        if otc.decode() != new_client['otc']:
            return False
        if not utils.verify_signature(new_client['public_key'], otc, signature):
            return False
        
        print(f"Successfully registered {client_id}")
        new_client['has_session'] = True
        self.registered_clients[client_id] = new_client
        return True

    def handle_message_request(self, request_bytes):
        print("got message", request_bytes)

    def send_by_secure_channel(self, client_id, conn, client):
        otc = utils.generate_otc()
        client['otc'] = otc
        conn.send(bytes(otc,"utf-8"))

    def read_private_key():
        private_key = serialization.load_pem_private_key(
            read_binary(resources, "server_private.pem"),
            password=None)
        return private_key

server = Server()
server.start()