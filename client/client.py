import socket
import os 
import time
import json
import pickle
import utils
import sys
import config
from peer import PeerStatus, Peer
from message import Message
import my_requests as requests
from logger import logger
from cryptography.hazmat.primitives.asymmetric import rsa
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
        self.conn_lock = Lock()
        self.conn = None
        self.is_registered = False
        self.outgoing_messages = []
        self.load_state()
        self.load_peers()
        self.init_connection()
        self.sync()
        self.recv_messages()
        logger.debug(f"self public key: {self.get_public_key_bytes()}")
    
    def init_connection(self):
        self.conn = self.socket.connect((config.SERVER_HOST, config.SERVER_PORT))
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
        try:
            state_json_file = json.load(importlib.resources.open_text(resources, f"{self.id}-state.json"))
            self.is_registered = state_json_file["is_registered"]
        except Exception as e:
            logger.error(f"Couldn't load state - {e}")
    
    def load_peers(self):
        logger.debug("Loading peers from file")
        try:
            peers_file = pickle.load(importlib.resources.open_binary(resources, f"{self.id}-peers.pkl"))
            self.peers = peers_file
        except Exception as e:
            logger.error(f"Couldn't load peers - {e}")
    
    def update_peers(self):
        with open(f"{os.path.dirname(__file__)}/resources/{self.id}-peers.pkl", "wb") as peers_file:
            pickle.dump(self.peers, peers_file)

    
    def update_state(self):
        state = {
            "is_registered": self.is_registered
        }
        with open(f"{os.path.dirname(__file__)}/resources/{self.id}-state.json", "w") as state_file:
            json.dump(state, state_file)
        
    
    def register(self):
        public_key_bytes = self.get_public_key_bytes()
        reg_request = requests.register(self.id, public_key_bytes)
        self.socket.send(reg_request)

        otc = self.socket.recv(6)
        logger.debug(f"Got OTC over \"secured\" channel {otc}")
        verify_otc_req = requests.verify_otc(otc, lambda x: utils.encrypt(self.server_public_key, x), self.sign)
        self.socket.send(verify_otc_req)
        self.is_registered = True
        self.update_state()
    
    def connect(self):
        connect_req = requests.connect(self.id, self.sign)
        self.socket.send(connect_req)
    

    def send_message(self, peer_id: str, message: str):
        peer = self.get_peer(peer_id)
        if peer.status == PeerStatus.UNKOWN:
            logger.debug("Unkonwn peer - exchanging symmeteric key")
            self.exchange_symmetric_key(peer_id)
        message_obj = Message(self.id, peer_id, message, str(peer.get_next_message_no()), str(time.time()))
        message_req = message_obj.to_bytes(peer.aes_encrypt, peer.generate_hmac)
        self.socket.send(message_req)
        peer.message_sent(message_obj)

    def close(self):
        self.socket.close()
        self.update_peers()
        self.update_state()

    def load_private_key(self):
        if importlib.resources.is_resource(resources,  f"{self.id}-private.pem"):
            logger.info("Found a private key, Loading..")
            return utils.load_private_key(importlib.resources.read_binary(resources, f"{self.id}-private.pem"))
        logger.info("Generating new RSA key pair")
        private = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        private_pem = utils.serialize_private_key(private)
        with open(os.path.dirname(__file__) + f"/resources/{self.id}-private.pem", "wb") as pri_file:
            pri_file.write(private_pem)
        return private
    
    def load_server_public_key():
        return utils.load_public_key(importlib.resources.read_binary(resources, "server.pem"))
    
    def get_public_key_bytes(self):
        return utils.serialize_public_key(self.public_key)
    
    def exchange_symmetric_key(self, peer_id):
        new_peer = self.get_peer(peer_id)
        if new_peer.status == PeerStatus.ASK:
            return
        if not new_peer.is_known():
            peer_pk = self.get_public_key_of_peer_from_server(peer_id)
            new_peer.set_public_key(peer_pk)
            logger.debug(f"Peer public key {utils.serialize_public_key(peer_pk)}")
            logger.info(f"Got public key of {peer_id} from server")
        
        exe_message_req = Message.syn_message_bytes(peer_id, lambda : new_peer.generate_shared_key(self.sign))
        logger.info(f"Generated new shared secret to send to {peer_id}, shared_secret={new_peer.shared_key}, share secret is encrypted with peer public key")
        self.socket.send(exe_message_req)
        new_peer.status = PeerStatus.ASK


    def get_public_key_of_peer_from_server(self, peer_id: str):
        """
        Will make a blocking call to server asking for peer public key
        """
        get_pk_req = requests.public_key(peer_id, self.sign)
        response_pk = None
        with self.conn_lock:
            self.socket.send(get_pk_req)
            response_pk = self.socket.recv(4096)
        logger.debug(f"PK response: {response_pk}")
        peer_pk, signature = response_pk[:451], response_pk[451:]
        if utils.verify_signature(self.server_public_key, peer_pk, signature):
            return utils.load_public_key(peer_pk)
        raise Exception("Couldn't verify response peer pk response")
    
    def get_all_messages_from_server(self):
        self.socket.send(requests.get_messages())
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
    
    def handle_new_incoming_messages(self, messages: bytes):
        messages = messages.split(b'message ')
        for message in messages:
            if len(message) < 2:
                continue
            header, payload = message.split(b'\n\n', 1)
            peer_id, msg_id = header.split(b' ')
            peer_id = peer_id.decode()
            msg_type, msg = payload[:3], payload[3:]
            logger.debug(f"Got message from {peer_id}, msg_type={msg_type}, payload={msg}")
            peer = self.get_peer(peer_id)
            logger.debug(str(self.peers))

            if msg_type == b'SYN':
                sender_public_key = msg[:451]
                message_content = msg[451:-256]
                signature = msg[-256:]
                if not utils.verify_signature(self.server_public_key, payload[:-256], signature):
                    logger.error(f"Couldn't verify signature of SYN message from {peer_id}")
                    continue

                logger.debug(f"Got public key of {peer_id} from server in SYN message - public key {sender_public_key}")
                message_content, signature = message_content[:-256], message_content[-256:]
                shared_secret = utils.decrypt(self.private_key, message_content)
                sender_pk = utils.load_public_key(sender_public_key)
                
                logger.debug("Verifying signature of shared secret using sender public key")
                if not utils.verify_signature(sender_pk, shared_secret, signature):
                    logger.error(f"Couldn't verify signature of shared secret from {peer_id}")
                    continue
                
                peer.set_public_key(sender_pk)
                peer.set_shared_key(shared_secret)
            
            if msg_type == b'MSG':
                if not peer.shared_key:
                    logger.debug(f"No shared key with peer {peer_id}, skipping message")
                    continue
                try:
                    logger.info("Starting decrypting and verifying message")
                    msg_obj = Message.from_bytes(header, msg, self.id, str(time.time()), peer.aes_decrypt, peer.generate_hmac)
                    peer.message_received(msg_obj)
                except Exception as e:
                    logger.error(e)
                else:
                    logger.debug(f"Decrypted message: {msg_obj.content}")
                    with self.conn_lock:
                        self.socket.send(Message.ack_message_bytes(msg_obj.msg_id, peer_id, peer.generate_hmac))
            
            if msg_type == b'ACK':
                logger.info("Veryfying HMAC of ACK")
                if peer.verify_hmac(f"{self.id} {msg_id.decode()}", msg):
                    peer.ack_recieved(msg_id.decode())
                    logger.debug(f"Acknowledged message {msg_id}")
                else:
                    logger.error(f"Couldn't verify signature of message {msg_id} from {peer.id}")
                
    
    def recv_messages(self):
        def recv_message():
            while True:
                try:
                    sockets = [self.socket]
                    read_socket, _, _ = select(sockets, [], [])
                    if read_socket: 
                        message = None
                        with self.conn_lock:
                            message = self.socket.recv(4096)
                        if not message:
                            print("Server closed connection, exiting...")
                            logger.critical("Server closed connection")
                            exit(1)
                        
                        logger.info(f"Got new message {message}")
                        self.handle_new_incoming_messages(message)
                except OSError:
                    logger.exception("Error in recv_message loop, connection is closed")
                    break
                except Exception as e:
                    logger.exception(e)
        Thread(target=recv_message).start()
    
    def get_peer(self, peer_id):
        peer = self.peers.get(peer_id, Peer(peer_id))
        self.peers[peer_id] = peer
        return peer
    
    def show_peers(self):
        peers_str = "\n".join([f"{peer[0]} : {peer}" for peer in sorted(self.peers.keys())])
        if not peers_str:
            print("No peers yet :(")
        else:
            print(peers_str)
    
    def sign(self, msg: bytes):
        logger.debug(f"Signing message {msg} with self private key")
        return utils.sign(self.private_key, msg)




