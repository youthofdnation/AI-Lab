# uvicorn get_example:app

# http://localhost:8000/redoc
# http://localhost:8000/items
# http://localhost:8000/items/1

from fastapi import FastAPI, HTTPException
import uvicorn

app = FastAPI(title="FastAPI GET 요청 예제")

items_db = {
    1: {"name": "노트북", "price": 1500000},
    2: {"name": "스마트폰", "price": 1000000},
    3: {"name": "헤드폰", "price": 300000}
}

@app.get("/")
async def root():
    return {"message": "FastAPI GET 요청 예제에 오신 것을 환영합니다!"}

@app.get("/items")
async def get_items():
    return items_db

@app.get("/items/{item_id}")
async def get_item(item_id: int):
    if item_id not in items_db:
        raise HTTPException(status_code=404, detail="아이템을 찾을 수 없습니다")
    return items_db[item_id]

if __name__ == "__main__":
    uvicorn.run("get_example:app", host="0.0.0.0", port=8000, reload=True)