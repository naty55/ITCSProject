import socket
import os 
import time
import json
import utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
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
        self.conn = None
        self.is_registered = False
        self.outgoing_messages = [] 
        self.load_state()
        self.init_connection()
    
    def init_connection(self):
        self.conn = self.socket.connect(("localhost", 6789))
        if self.is_registered:
            print("Connecting...")
            self.connect()
        else:
            print("Registering...")
            self.register()

    def load_state(self):
        state_json_file = json.load(importlib.resources.open_text(resources, "state.json"))
        self.is_registered = state_json_file["is_registered"]
        self.peers = state_json_file["peers"]

    
    def update_state(self):
        state = {
            "is_registered": self.is_registered,
            "peers": self.peers
        }
        with open(os.path.dirname(__file__) + "/resources/state.json", "w") as state_file:
            json.dump(state, state_file)
    
    def register(self):
        public_key_bytes = self.get_public_key_bytes()
        reg_request = b'register ' + bytes(self.id, 'utf-8') + b'\n\n' + public_key_bytes
        self.socket.send(reg_request)

        otc = self.socket.recv(6)
        print(f"Got OTC over \"secured\" channel {otc}")
        enc_otc = self.server_public_key.encrypt(otc, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                         algorithm=hashes.SHA256(),
                                                         label=None))
        verify_otc_req = b'verify_otc\n\n'
        signature = self.private_key.sign(otc, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
            )
        verify_otc_req += enc_otc + signature
        self.socket.send(verify_otc_req)
        self.is_registered = True
        self.update_state()
    
    def connect(self):
        id_bytes = bytes(self.id + '-hello-' + str(time.time()), "utf-8")
        connect_req = b'connect ' + id_bytes + b'\n\n'
        signature = self.private_key.sign(id_bytes, padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
            )
        connect_req += signature
        self.socket.send(connect_req)
    

    def send_message(self, peer_id, message):
        if peer_id not in self.peers or not self.peers[peer_id].get('shared_key', None):
            print("Unkonwn client - exchanging symmeteric key")
            self.exchange_symmetric_key(peer_id)
            self.outgoing_messages.append({"to": peer_id, "message": message})
            return
        # Client.aes_encrypt(bytes(message, 'utf-8'))
        message_req = b'message ' + bytes(peer_id, "utf-8") + b"\n\n" + bytes(message, "utf-8")
        self.socket.send(message_req)

    def close(self):
        self.socket.close()

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
    
    def exchange_symmetric_key(self, peer_id):
        new_peer = self.peers.get(peer_id, dict({"message_counter": 0}))
        if new_peer.get('status', None) == 'ASK':
            return
        peer_pk = new_peer.get('public_key', None)
        if not peer_pk:
            peer_pk = self.get_public_key_of_peer_from_server(peer_id)
            new_peer['public_key'] = peer_pk
            print(f"Got public key of {peer_id} from server")
        
        shared_key = os.urandom(32)
        exe_message_req = b'message ' + bytes(peer_id, 'utf-8') + b'\n\nSYN' 
        encrypted_syn_message = utils.encrypt(peer_pk, shared_key)
        exe_message_req += encrypted_syn_message
        self.socket.send(exe_message_req)

        new_peer['status'] = 'ASK'
        new_peer['shared_key'] = shared_key
        self.peers[peer_id] = new_peer


    def get_public_key_of_peer_from_server(self, peer_id):
        """
        Will make a blocking call to server asking for peer public key
        """
        get_pk_req = b'get_public_key ' + bytes(peer_id, 'utf-8')
        signature = utils.sign(self.private_key, get_pk_req)
        get_pk_req += b'\n\n' + signature
        self.socket.send(get_pk_req)
        response_pk = self.socket.recv(4096)
        peer_pk, signature = response_pk[:451], response_pk[451:]
        if utils.verify_signature(self.server_public_key, peer_pk, signature):
            return serialization.load_pem_public_key(peer_pk)
        raise Exception("Couldn't verify response peer pk response")
    
    def get_all_messages_from_server(self):
        self.socket.send(b'get_messages\n\n')
        # print(f"Recieving {no_of_messages} new messages..")
        messages = b''
        while not messages.endswith(b'----DONE----'):
            data = self.socket.recv(4096)
            if not data:
                break
            messages += data
        print(messages)
        self.handle_new_incoming_messages(messages[:-12])
    
    def handle_new_incoming_messages(self, messages):
        messages = messages.split(b'message ')
        print(messages)
        for message in messages:
            if len(message) < 2:
                continue
            peer_id, payload = message.split(b'\n\n')
            peer_id = peer_id.decode()
            msg_type, msg = payload[:3], payload[3:]
            print(f"Got message from {peer_id}, msg_type={msg_type}, payload={msg}")
            
            if msg_type == b'SYN':
                if peer_id not in self.peers:
                    peer_pk = self.get_public_key_of_peer_from_server(peer_id)
                    new_peer = {"public_key": peer_pk}

                pass
            

    def aes_encrypt(key, plaintext):
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext
    
    def aes_decrypt(key, iv_ciphertext):
        iv = iv_ciphertext[:16]
        ciphertext = iv_ciphertext[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext


