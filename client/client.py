import socket
import os 
import time
import json
import utils
import sys
from peer import PeerStatus, Peer
from message import Message
from logger import logger
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import importlib.resources 
import resources
from select import select
from threading import Thread, Lock

class Client:
    def __init__(self, client_id):
        self.id = client_id
        self.private_key = self.load_private_key()
        self.public_key = self.private_key.public_key()
        self.server_public_key = Client.load_server_public_key()
        self.peers: dict[str, Peer] = dict()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn_is_used = Lock()
        self.conn = None
        self.is_registered = False
        self.outgoing_messages = []
        self.load_state()
        self.init_connection()
        self.sync()
        self.recv_messages()
        logger.debug(f"self public key: {self.get_public_key_bytes()}")
    
    def init_connection(self):
        self.conn = self.socket.connect(("localhost", 6789))
        if self.is_registered:
            logger.debug("Registered, connecting to server...")
            self.connect()
        else:
            logger.debug("Not registered, registering...")
            self.register()
    
    def sync(self):
        if self.socket:
            self.get_all_messages_from_server()
        else:
            logger.critical("No connection to server")
            sys.exit(1)

    def load_state(self):
        logger.debug("Loading state from file")
        state_json_file = json.load(importlib.resources.open_text(resources, f"{self.id}-state.json"))
        self.is_registered = state_json_file["is_registered"]
        # self.peers = state_json_file["peers"]

    
    def update_state(self):
        state = {
            "is_registered": self.is_registered,
            # "peers": self.peers
        }
        with open(f"{os.path.dirname(__file__)}/resources/{self.id}-state.json", "w") as state_file:
            json.dump(state, state_file)
    
    def register(self):
        public_key_bytes = self.get_public_key_bytes()
        reg_request = b'register ' + bytes(self.id, 'utf-8') + b'\n\n' + public_key_bytes
        self.socket.send(reg_request)

        otc = self.socket.recv(6)
        logger.debug(f"Got OTC over \"secured\" channel {otc}")
        enc_otc = utils.encrypt(self.server_public_key, otc)
        verify_otc_req = b'verify_otc\n\n'
        signature = utils.sign(self.private_key, otc)
        verify_otc_req += enc_otc + signature
        self.socket.send(verify_otc_req)
        self.is_registered = True
        self.update_state()
    
    def connect(self):
        id_bytes = bytes(self.id + '-hello-' + str(time.time()), "utf-8")
        connect_req = b'connect ' + id_bytes + b'\n\n'
        signature = utils.sign(self.private_key, id_bytes)
        connect_req += signature
        self.socket.send(connect_req)
    

    def send_message(self, peer_id: str, message: str):
        peer = self.get_peer(peer_id)
        if peer.status == PeerStatus.UNKOWN:
            logger.debug("Unkonwn peer - exchanging symmeteric key")
            self.exchange_symmetric_key(peer_id)
        message = Message(self.id, peer_id, message, str(peer.get_next_message_no()), str(time.time()))
        message_req = message.to_bytes(peer.aes_encrypt)
        print(message_req)
        self.socket.send(message_req)
        peer.message_sent(message)

    def close(self):
        self.socket.close()

    def load_private_key(self):
        if importlib.resources.is_resource(resources,  f"{self.id}-private.pem"):
            return serialization.load_pem_private_key(
                importlib.resources.read_binary(resources, f"{self.id}-private.pem"), password=None)
        logger.info("Generating new RSA key pair")
        private = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        private_pem = private.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption()
                                            )
        with open(os.path.dirname(__file__) + f"/resources/{self.id}-private.pem", "wb") as pri_file:
            pri_file.write(private_pem)
        return private
    
    def load_server_public_key():
        return serialization.load_pem_public_key(importlib.resources.read_binary(resources, "server.pem"))
    
    def get_public_key_bytes(self):
        return self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    def exchange_symmetric_key(self, peer_id):
        new_peer = self.get_peer(peer_id)
        if new_peer.status == PeerStatus.ASK:
            return
        if not new_peer.is_known():
            peer_pk = self.get_public_key_of_peer_from_server(peer_id)
            new_peer.set_public_key(peer_pk)
            logger.debug(f"Peer public key {peer_pk.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)}")
            logger.info(f"Got public key of {peer_id} from server")
        
        shared_key_encrypted = new_peer.generate_shared_key()
        logger.info(f"Generated new shared secret to send to {peer_id}, shared_secret={new_peer.shared_key}")
        exe_message_req = b'message ' + bytes(peer_id, 'utf-8') + b' 0\n\nSYN' 
        exe_message_req += shared_key_encrypted
        logger.debug(f"Encrypted shared secret '{shared_key_encrypted}'")
        self.socket.send(exe_message_req)
        new_peer.status = PeerStatus.ASK


    def get_public_key_of_peer_from_server(self, peer_id):
        """
        Will make a blocking call to server asking for peer public key
        """
        get_pk_req = b'get_public_key ' + bytes(peer_id, 'utf-8')
        signature = utils.sign(self.private_key, get_pk_req)
        get_pk_req += b'\n\n' + signature
        response_pk = None
        with self.conn_is_used:
            self.socket.send(get_pk_req)
            response_pk = self.socket.recv(4096)
        logger.debug(f"PK response: {response_pk}")
        peer_pk, signature = response_pk[:451], response_pk[451:]
        if utils.verify_signature(self.server_public_key, peer_pk, signature):
            return serialization.load_pem_public_key(peer_pk)
        raise Exception("Couldn't verify response peer pk response")
    
    def get_all_messages_from_server(self):
        self.socket.send(b'get_messages\n\n')
        messages = b''
        while not messages.endswith(b'----DONE----'):
            data = self.socket.recv(4096)
            if not data:
                break
            messages += data
        logger.debug(f"{messages}")
        self.handle_new_incoming_messages(messages[:-12])
    
    def show_messages(self, peer_id: str):
        if peer_id not in self.peers:
            print("No messages from this peer")
            return
        for message in self.peers[peer_id].messages:
            print(message)
    
    def handle_new_incoming_messages(self, messages):
        messages = messages.split(b'message ')
        for message in messages:
            if len(message) < 2:
                continue
            header, payload = message.split(b'\n\n')
            peer_id, msg_id = header.split(b' ')
            peer_id = peer_id.decode()
            msg_type, msg = payload[:3], payload[3:]
            logger.debug(f"Got message from {peer_id}, msg_type={msg_type}, payload={msg}")
            peer = self.get_peer(peer_id)
            logger.debug(str(self.peers))
            
            if msg_type == b'SYN':
                shared_secret = utils.decrypt(self.private_key, msg)
                peer.set_shared_key(shared_secret)
                logger.debug(f"Shared secret {shared_secret}")
            
            if msg_type == b'MSG':
                if not peer.shared_key:
                    logger.debug(f"No shared key with peer {peer_id}, skipping message")
                    continue
                msg_obj = Message.from_bytes(header, msg, self.id, str(time.time()), peer.aes_decrypt)
                peer.message_received(msg_obj)
                logger.debug(f"Decrypted message: {msg_obj.content}")
                with self.conn_is_used:
                    self.socket.send(Message.ack_message_bytes(msg_obj.msg_id, peer_id))
            
            if msg_type == b'ACK':
                peer.ack_recieved(msg_id.decode())
                logger.debug(f"Acknowledged message {msg_id}")
    
    def recv_messages(self):
        def recv_message():
            while True:
                sockets = [self.socket]
                read_socket, _, _ = select(sockets, [], [])
                if read_socket: 
                    message = None
                    with self.conn_is_used:
                        message = self.socket.recv(4096)
                    if not message:
                        print("Server closed connection")
                        logger.critical("Server closed connection")
                        exit(1)
                    
                    logger.info(f"Got new message {message}")
                    self.handle_new_incoming_messages(message)
        Thread(target=recv_message).start()
    
    def get_peer(self, peer_id):
        peer = self.peers.get(peer_id, Peer(peer_id))
        self.peers[peer_id] = peer
        return peer




