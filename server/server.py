import socket
from threading import Thread, Lock
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
        print("Starting server...")
        print(f"Listening on {SERVER_HOST}:{SERVER_PORT}")
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
        header, payload = data.split(b'\n\n', 1)
        req_type, client_id = header.split(b' ')
        client_id = client_id.decode()
        if req_type == b'register':
            if not self.handle_register_request(conn, client_id, payload):
                conn.close()
                return
            client = self.registered_clients[client_id]
        elif req_type == b'connect':
            client = self.handle_connect_request(conn, client_id, payload)
            
        if client:
            self.messages_loop(client, conn)
        
    def messages_loop(self, client, conn):
        # Connection stays open for next requests
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    client['has_session'] = False
                    del client['conn']
                    break
                if data.startswith(b'get_public_key'):
                    self.handle_get_public_key(data, client, conn)
                elif data.startswith(b'get_messages'):
                    self.handle_get_all_messages(data, client, conn)
                else:
                    self.handle_message_request(data, client, conn)
            except ConnectionResetError:
                client['has_session'] = False
                del client['conn']
                break

    def handle_register_request(self, conn, client_id, payload):
        if not utils.validate_client_id(client_id):
            return False
        print(f"Client {client_id} is trying to register")
        
        if client_id in self.registered_clients:
            return False
        
        new_client = dict()
        new_client['id'] = client_id
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
        new_client['conn'] = conn
        new_client['conn_mutex'] = Lock()
        new_client['has_session'] = True
        new_client['incoming_messages'] = []
        self.registered_clients[client_id] = new_client
        return True
    
    def handle_connect_request(self, conn, message, payload):
        signed_text_message = message
        client_id = message.split('-', 1)[0]
        if client_id not in self.registered_clients:
            print(f"Client id {client_id} is not a registered user - connection denied")
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
        client['conn'] = conn
        client['conn_mutex'] = Lock()
        client['has_session'] = True
        return client
    
    def handle_get_public_key(self, request_bytes, client, conn):
        header, signature = request_bytes.split(b'\n\n', 1)
        if not utils.verify_signature(client['public_key'], header, signature):
            print(f"Coludn't verify client request for public key, client_id={client['id']}")
            return False
        
        req_type, peer_id = header.split(b' ')
        peer_id = peer_id.decode()
        print(f"peer {client['id']} is asking for {peer_id}'s public key")

        if req_type != b'get_public_key':
            return

        if peer_id not in self.registered_clients:
            print(f"Peer id {peer_id} is not a registered user - request denied")
            return

        peer = self.registered_clients[peer_id]
        public_key_bytes = utils.serialize_public_key(peer['public_key'])
        signature = utils.sign(self.pri_key, public_key_bytes)
        
        with client['conn_mutex']:
            conn.send(public_key_bytes + signature)

    def handle_get_all_messages(self, request_bytes, client, conn):
        print(f'{client["id"]} is asking all waiting messages')
        messages_to_send = client.get("messages", [])
        messages_bytes = b''.join(messages_to_send)
        messages_bytes += b'----DONE----'
        conn.send(messages_bytes)
        sent_messages = client.get("sent_messages", [])
        sent_messages.extend(messages_to_send)
        client['sent_messages'] = sent_messages
        client['messages'] = []
        

    def handle_message_request(self, request_bytes, client, conn):
        print(request_bytes)
        header, payload = request_bytes.split(b'\n\n')
        print(header)
        req_type, peer_id, msg_id  = header.split(b' ')
        if req_type != b'message':
            return 
        peer_id = peer_id.decode()
        if peer_id not in self.registered_clients:
            print(f"Peer id '{peer_id}' not found")
            return 
        peer = self.registered_clients[peer_id]
        print(f"Message from {client['id']} to {peer_id}: {payload}")

        message = b'message ' + bytes(client['id'], 'utf-8') + b' ' + msg_id + b'\n\n' + payload
        
        if peer['has_session']:
            peer_conn = peer['conn']
            with peer['conn_mutex']:
                peer_conn.send(message)
        else:
            messages = peer.get("messages", [])
            peer['messages'] = messages
            if len(messages) >= 10:
                print(f"Inbox of peer {peer_id} is full")
                return 
            messages.append(message)

    def SendBySecureChannel(self, client_id, conn, client):
        """
        Simulate real sending OTC over secure channel to client 
        """
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