from client import Client

print("Welcome to E2EE client")
running = True
client = Client("111111111")
while running:
    command = input(">")
    if command == "init":
        client.register()
    if command == "connect":
        client.connect()
    if command.startswith("message "):
        command, peer_id, message = command.split(' ', 2)
        client.send_message(peer_id, message)

    running = command != "exit"
client.close()
print("Yalla bye!")