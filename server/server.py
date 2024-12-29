import socket
from threading import Thread
from config import SERVER_HOST, SERVER_PORT
from cryptography.hazmat.primitives import serialization
import resources
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
                print("Accepted")
                Thread(target=Server.handle_connection, args=(conn,)).start()
    
    def handle_connection(conn):
        while True:
            print("Reading data from socket")
            data = conn.recv(4096)
            if not data:
                break
            print(data)
        

    def send_by_secure_channel(phone_number, conn):
        pass

    def read_private_key():
        private_key = serialization.load_pem_private_key(
            read_binary(resources, "server_private.pem"),
            password=None)
        return private_key

server = Server()
server.start()