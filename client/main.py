from client import Client
import os


running = True
client_id = os.environ["client_id"].strip()

def handle_user_command(command, client):
    global running
    if command.startswith("message ") or command.startswith("m "):
        command, peer_id, message = command.split(' ', 2)
        client.send_message(peer_id.strip(), message)
    if command.startswith("show ") or command.startswith("s "):
        command, peer_id = command.split(' ', 1)
        client.show_messages(peer_id.strip())
    running = command != "exit"

def main_loop(client):
    print("Welcome to E2EE client")
    print(f"Client id: {client.id}")
    print("show command to show chat with other peer, e.g. 'show 111111111' you can also use s as shortcut e.g. s 111111111")
    print("message command to send message to another peer, e.g. 'message 111111111 hello' you can also use m as shortcut")
    global running
    while running:
        try: 
            command = input(">")
            handle_user_command(command, client)
        except KeyboardInterrupt:
            running = False
    client.close()
    print("Yalla bye!")

if __name__ == "__main__":
    client = Client(client_id)
    main_loop(client)
    