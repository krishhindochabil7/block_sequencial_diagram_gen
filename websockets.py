import asyncio

import websockets

import json

import uuid
 
users = {}  # username: password

sessions = {}  # websocket: username

connected_users = {}  # username: websocket
 
 
async def handle_client(websocket, path):

    async for message in websocket:

        try:

            data = json.loads(message)

            action = data.get("action")

            if action == "register":

                username = data["username"]

                password = data["password"]

                if username in users:

                    await websocket.send(json.dumps({"status": "error", "message": "User already exists"}))

                else:

                    users[username] = password

                    await websocket.send(json.dumps({"status": "success", "message": "Registration successful"}))
 
            elif action == "login":

                username = data["username"]

                password = data["password"]

                if users.get(username) == password:

                    sessions[websocket] = username

                    connected_users[username] = websocket

                    await websocket.send(json.dumps({"status": "success", "message": "Login successful"}))

                else:

                    await websocket.send(json.dumps({"status": "error", "message": "Invalid credentials"}))
 
            elif action == "access_service":

                username = sessions.get(websocket)

                if not username:

                    await websocket.send(json.dumps({"status": "error", "message": "Unauthorized"}))

                    continue

                service = data["service"]

                if service == "service1":

                    await websocket.send(json.dumps({"status": "success", "result": f"Result of service 1 for {username}"}))

                elif service == "service2":

                    await websocket.send(json.dumps({"status": "success", "result": f"Result of service 2 for {username}"}))

                else:

                    await websocket.send(json.dumps({"status": "error", "message": "Unknown service"}))
 
        except Exception as e:

            await websocket.send(json.dumps({"status": "error", "message": f"Exception: {str(e)}"}))
 
 
async def periodic_events():

    while True:

        await asyncio.sleep(10)

        if connected_users:

            for username, ws in connected_users.items():

                try:

                    await ws.send(json.dumps({"event": "server_update", "message": f"Hello {username}, here's a periodic update!"}))

                except:

                    pass
 
 
async def main():

    async with websockets.serve(handle_client, "localhost", 8765):

        await periodic_events()
 
asyncio.run(main())

 