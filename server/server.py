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
        self.clients = dict()
    
    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((SERVER_HOST, SERVER_PORT))
            s.listen(10)
            while True:
                conn, addr = s.accept()
                print(f"Accepted connection from {addr}")
                Thread(target=self.handle_new_connection, args=(conn,)).start()
    
    def handle_new_connection(self, conn):
        data = conn.recv(4096)
        header, payload = data.split(b'\n\n', 1)
        req_type, client_id = header.split(b' ')
        if req_type == b'register':
            self.handle_register_request(conn)
        elif req_type == b'connect':
            if client_id not in self.clients or not self.clients[client_id]['registerd']:
                raise

        # Connection stays open for next requests
        while True:
            data = conn.recv(4096)
            if not data:
                self.clients[client_id]['has_session'] = False
                break
            self.handle_message_request(data)
        
    def handle_register_request(self, conn, client_id, payload):
        client_id = client_id.decode()
        if not utils.validate_client_id(client_id):
            return False
        print(f"Client {client_id} is trying to register")
        new_client = dict()
        self.clients[client_id] = new_client
        new_client['public_key'] = serialization.load_pem_public_key(payload)
        self.send_by_secure_channel(client_id, conn)
        data = conn.recv(4096)
        
        header, payload = data.split(b'\n\n', 1)
        req_type, otc = header.split(b' ')
        if req_type != b'verify_otc':
            raise
        print(f"Recieved otc from client, client id {client_id}, otc={otc}")
        registration_failed = False
        if otc.decode() != new_client['otc']:
            registration_failed = True
        else:
            if not utils.verify_signature(new_client['public_key'], otc, payload):
                registration_failed = True
            new_client['registerd'] = True
            new_client['has_session'] = True
        if registration_failed:
            del self.clients[client_id]

        return not registration_failed

    def handle_message_request(self, request_bytes):
        print("got message", request_bytes)

    def send_by_secure_channel(self, client_id, conn):
        otc = utils.generate_otc()
        self.clients[client_id]['otc'] = otc
        conn.send(bytes(otc,"utf-8"))

    def read_private_key():
        private_key = serialization.load_pem_private_key(
            read_binary(resources, "server_private.pem"),
            password=None)
        return private_key

server = Server()
server.start()