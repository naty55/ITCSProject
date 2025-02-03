from client import Client
import os
import utils
from logger import logger

running = True
client_id = os.environ["client_id"].strip()

def print_help():
    print("show command to show chat with other peer, e.g. 'show 111111111' you can also use s as shortcut e.g. s 111111111")
    print("message command to send message to another peer, e.g. 'message 111111111 hello' you can also use m as shortcut")

def handle_user_command(command: str, client: Client):
    command = command.strip()
    global running
    if command.startswith("message ") or command.startswith("m ") or command.startswith("ms "):
        command, peer_id, message = command.split(' ', 2)
        if len(peer_id) == 1:
            peer_id = peer_id * 9
        if utils.validate_client_id(peer_id):
            client.send_message(peer_id.strip(), message)
            if command == "ms":
                client.show_messages(peer_id.strip())
        else:
            print(f"'{peer_id}' is not a valid peer id")
    
    if command.startswith("show ") or command.startswith("s ") or command.strip() == 's':
        if command.strip() == 's':
            client.show_peers()
            return
        command, peer_id = command.split(' ', 1)
        if len(peer_id) == 1: # Tricks only for demo - in real life logic is more complex
            peer_id = peer_id * 9
        if utils.validate_client_id(peer_id):
            client.show_messages(peer_id.strip())
        else:
            print("Invalid peer id, command help for help prompt")
    if command == "help":
        print_help()

    running = command != "exit" and command != "e"

def main_loop(client: Client):
    print("Welcome to E2EE client")
    print(f"Client id: {client.id}")
    print_help()
    global running
    while running:
        try: 
            command = input(">")
            logger.debug(f"Got command {command}")
            handle_user_command(command, client)
        except KeyboardInterrupt:
            running = False
        except Exception as e:
            logger.exception(f"Error in main loop - {e}")
        
    client.close()
    print("Yalla bye!")

if __name__ == "__main__":
    client = Client(client_id)
    main_loop(client)
    