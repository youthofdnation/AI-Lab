from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from typing import List
import uvicorn
import json
from datetime import datetime

app = FastAPI(title="FastAPI WebSocket 예제")

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)
    
    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

@app.get("/")
async def root():
    return {"message": "FastAPI WebSocket 예제에 오신 것을 환영합니다!"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            message_data = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "message": data,
                "client_id": id(websocket) % 10000 
            }
            
            await manager.send_personal_message(
                f"당신: {data}", websocket
            )
            
            await manager.broadcast(
                json.dumps(message_data)
            )
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        disconnect_message = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "message": f"클라이언트 #{id(websocket) % 10000}이(가) 나갔습니다.",
            "client_id": "system"
        }
        await manager.broadcast(json.dumps(disconnect_message))

if __name__ == "__main__":
    uvicorn.run("websocket_example:app", host="0.0.0.0", port=8000, reload=True)