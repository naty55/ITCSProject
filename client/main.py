from client import Client
import os 


running = True
client_id = os.environ["client_id"]
client = Client(client_id)

print("Welcome to E2EE client")
print(f"Client id: {client_id}")

while running:
    command = input(">")
    if command == "init":
        client.register()
    if command == "connect":
        client.connect()
    if command.startswith("message "):
        command, peer_id, message = command.split(' ', 2)
        client.send_message(peer_id, message)
    if command == "sync":
        client.get_all_messages_from_server()

    running = command != "exit"
client.close()
print("Yalla bye!")