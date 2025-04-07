# uvicorn post_example:app

# http://localhost:8000/redoc

# 새 아이템 생성
# curl -X POST -H "Content-Type: application/json" -d '{"name": "태블릿", "price": 500000}' http://localhost:8000/items

# 아이템 업데이트
# curl -X PUT -H "Content-Type: application/json" -d '{"name": "고급 노트북", "price": 2000000}' http://localhost:8000/items/1

# 사용자 등록
# curl -X POST -H "Content-Type: application/json" -d '{"username": "bardroh", "email": "bardroh@weable.ai", "password": "secret123"}' http://localhost:8000/register

from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="FastAPI POST 요청 예제")

items_db = {}
counter = 0

class Item(BaseModel):
    name: str
    description: str = None
    price: float

class UserRegistration(BaseModel):
    username: str
    email: str
    password: str

@app.get("/")
async def root():
    return {"message": "FastAPI POST 요청 예제에 오신 것을 환영합니다!"}

@app.post("/items")
async def create_item(item: Item):
    global counter
    counter += 1
    items_db[counter] = item.dict()
    return {"id": counter, "item": items_db[counter]}

@app.put("/items/{item_id}")
async def update_item(item_id: int, item: Item):
    if item_id not in items_db:
        return {"error": "아이템을 찾을 수 없습니다"}
    
    items_db[item_id] = item.dict()
    return {"id": item_id, "item": items_db[item_id]}

@app.post("/register")
async def register_user(user: UserRegistration):
    return {
        "username": user.username,
        "email": user.email,
        "message": "사용자가 성공적으로 등록되었습니다"
    }

@app.get("/items")
async def get_items():
    return items_db

if __name__ == "__main__":
    uvicorn.run("post_example:app", host="0.0.0.0", port=8000, reload=True)