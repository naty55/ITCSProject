import socket
from threading import Thread, Lock
from config import SERVER_HOST, SERVER_PORT
import resources
import utils
from time import time
from objects import Request, Client
from importlib.resources import read_binary

class Server:
    def __init__(self):
        self.socket = None
        self.pri_key = Server.read_private_key()
        self.pub_key = self.pri_key.public_key()
        self.registered_clients: dict[str, Client] = dict()
    
    def start(self):
        print("Starting server...")
        print(f"Listening on {SERVER_HOST}:{SERVER_PORT}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((SERVER_HOST, SERVER_PORT))
            s.listen(10)
            while True:
                conn, addr = s.accept()
                print(f"Accepted connection from {addr}")
                Thread(target=self.handle_new_connection, args=(conn,)).start()
    
    def handle_new_connection(self, conn: socket.socket):
        data = conn.recv(4096)
        request = Request.from_bytes(data)
        client = None
        client_id = request.header_fields[0].decode()
        if request.is_of_type('register'):
            if not self.handle_register_request(conn, client_id, request.payload):
                conn.close()
                return
            client = self.registered_clients[client_id]
        elif request.is_of_type('connect'):
            client = self.handle_connect_request(conn, client_id, request.payload)
            
        if client:
            self.messages_loop(client, conn)
        
    def messages_loop(self, client: Client, conn: socket.socket):
        # Connection stays open for next requests
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    client.disconnect()
                    break
                request = Request.from_bytes(data)
                if request.is_of_type('get_public_key'):
                    self.handle_get_public_key(request, client, conn)
                elif request.is_of_type('get_messages'):
                    self.handle_get_all_messages(request, client, conn)
                elif request.is_of_type('message'):
                    self.handle_message_request(request, client, conn)
                else: 
                    print("Unknown request type")
            except ConnectionResetError:
                client.disconnect()
                break

    def handle_register_request(self, conn: socket.socket, client_id: str, payload: bytes):
        if not utils.validate_client_id(client_id):
            return False
        print(f"Client {client_id} is trying to register")
        
        if client_id in self.registered_clients:
            return False
        
        new_client = Client(client_id, utils.load_public_key(payload), conn, Lock(), True, [])
        self.SendBySecureChannel(client_id, conn, new_client)
        data = conn.recv(4096)
        otc_request = Request.from_bytes(data)
        if not otc_request.is_of_type('verify_otc'):
            return False
        
        otc_enc, signature = otc_request.payload[:256], otc_request.payload[256:]
        otc = utils.decrypt(self.pri_key, otc_enc)
        print(f"Recieved otc from client, client id {client_id}, otc={otc}")

        if not new_client.verify_otc(otc) or not new_client.verify_signature(otc, signature):
            return False
        
        print(f"Successfully registered {client_id}")
        self.registered_clients[client_id] = new_client
        return True
    
    def handle_connect_request(self, conn: socket.socket, message: str, payload: bytes):
        signed_text_message = message
        client_id = message.split('-', 1)[0]
        if client_id not in self.registered_clients:
            print(f"Client id {client_id} is not a registered user - connection denied")
            conn.close()
            return 

        client = self.registered_clients[client_id]
        if client.has_session:
            print(f"Client id {client_id} already has another session - connection denied")
            conn.close()
            return 

        if not utils.verify_signature(client.public_key, signed_text_message.encode(), payload):
            print(f"Client id {client_id} couldn't be verified - connection denied")
            conn.close()
            return 

        print(f"{client_id} has been successfully connected")
        client.conn = conn
        client.has_session = True
        return client
    
    def handle_get_public_key(self, request: Request, client: Client, conn: socket.socket):
        if not utils.verify_signature(client.public_key, request.header, request.payload):
            print(f"Coludn't verify client request for public key, client_id={client.client_id}")
            return False
        
        peer_id = request.header_fields[0].decode()
        print(f"peer {client.client_id} is asking for {peer_id}'s public key")
        if peer_id not in self.registered_clients:
            print(f"Peer id {peer_id} is not a registered user - request denied")
            return

        peer = self.registered_clients[peer_id]
        public_key_bytes = peer.get_public_key_bytes()
        signature = utils.sign(self.pri_key, public_key_bytes)
        
        with client.conn_lock:
            conn.send(public_key_bytes + signature)

    def handle_get_all_messages(self, request: Request, client: Client, conn: socket.socket):
        print(f'{client.client_id} is asking all waiting messages')
        messages_to_send = client.incoming_messages
        messages_bytes = b''.join(messages_to_send)
        messages_bytes += b'----DONE----'
        conn.send(messages_bytes)
        client.incoming_messages.clear()
        

    def handle_message_request(self, request: Request, client: Client, conn):
        print(request)
        peer_id, msg_id  = request.header_fields
        peer_id = peer_id.decode()

        if peer_id not in self.registered_clients:
            print(f"Peer id '{peer_id}' not found")
            return 
        
        peer = self.registered_clients[peer_id]
        print(f"Message from {client.client_id} to {peer_id}: {request.payload}")

        payload = request.payload
        public_key = client.get_public_key_bytes()
        if payload.startswith(b'SYN'):
            payload = b'SYN' + public_key + payload[3:]
            signature = utils.sign(self.pri_key, payload)
            payload += signature
            print(len(signature))

        message = f"message {client.client_id} {msg_id.decode()}\n\n".encode() + payload
        if not peer.recv_message(message):
            print(f"Inbox of peer {self.client_id} is full")


    def SendBySecureChannel(self, client_id: str, conn: socket.socket, client: Client):
        """
        Simulate real sending OTC over secure channel to client 
        """
        otc = utils.generate_otc()
        client.otc = otc
        client.otc_timestamp = time()
        conn.send(otc.encode())

    def read_private_key():
        return utils.load_private_key(read_binary(resources, "server_private.pem"))

server = Server()
server.start()
