import websockets
import asyncio
import time

async def connect_and_send():
    uri = "ws://localhost:8000/ws"
    
    async with websockets.connect(uri) as websocket:
        print("Connected to the WebSocket server")
        
        message1 = "안녕하세요! 첫 번째 메시지입니다."
        await websocket.send(message1)
        print(f"Sent: {message1}")
        
        response = await websocket.recv()
        print(f"Received: {response}")
        
        await asyncio.sleep(1)
        
        message2 = "1초 후 두 번째 메시지입니다."
        await websocket.send(message2)
        print(f"Sent: {message2}")

        while True:
            try:
                response = await websocket.recv()
                print(f"Received: {response}")
            except websockets.exceptions.ConnectionClosed:
                print("Connection closed")
                break

# Run the client
if __name__ == "__main__":
    asyncio.run(connect_and_send())