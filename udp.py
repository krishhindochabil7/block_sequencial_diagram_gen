import asyncio
import json

users = {}  # username: password
sessions = {}  # client_address: username
connected_users = {}  # username: client_address


class UDPServerProtocol:
    def __init__(self):
        pass

    def connection_made(self, transport):
        self.transport = transport
        print("UDP server started")

    def datagram_received(self, data, addr):
        message = data.decode()
        asyncio.create_task(self.handle_message(message, addr))

    async def handle_message(self, message, addr):
        try:
            data = json.loads(message)
            action = data.get("action")

            if action == "register":
                username = data["username"]
                password = data["password"]

                if username in users:
                    response = {"status": "error", "message": "User already exists"}
                else:
                    users[username] = password
                    response = {"status": "success", "message": "Registration successful"}

                self.transport.sendto(json.dumps(response).encode(), addr)

            elif action == "login":
                username = data["username"]
                password = data["password"]

                if users.get(username) == password:
                    sessions[addr] = username
                    connected_users[username] = addr
                    response = {"status": "success", "message": "Login successful"}
                else:
                    response = {"status": "error", "message": "Invalid credentials"}

                self.transport.sendto(json.dumps(response).encode(), addr)

            elif action == "access_service":
                username = sessions.get(addr)

                if not username:
                    response = {"status": "error", "message": "Unauthorized"}
                    self.transport.sendto(json.dumps(response).encode(), addr)
                    return

                service = data["service"]

                if service == "service1":
                    result = f"Result of service 1 for {username}"
                    response = {"status": "success", "result": result}

                elif service == "service2":
                    result = f"Result of service 2 for {username}"
                    response = {"status": "success", "result": result}

                else:
                    response = {"status": "error", "message": "Unknown service"}

                self.transport.sendto(json.dumps(response).encode(), addr)

        except Exception as e:
            error_response = {"status": "error", "message": f"Exception: {str(e)}"}
            self.transport.sendto(json.dumps(error_response).encode(), addr)


async def periodic_events(transport):
    while True:
        await asyncio.sleep(10)
        if connected_users:
            for username, addr in connected_users.items():
                try:
                    message = {"event": "server_update", "message": f"Hello {username}, here's a periodic update!"}
                    transport.sendto(json.dumps(message).encode(), addr)
                except Exception:
                    pass


async def main():
    loop = asyncio.get_running_loop()

    # Create datagram endpoint
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPServerProtocol(),
        local_addr=("localhost", 8765),
    )

    # Run periodic events alongside UDP server
    try:
        await periodic_events(transport)
    finally:
        transport.close()


asyncio.run(main())
