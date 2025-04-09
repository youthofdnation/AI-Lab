from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any
import openai
import os
from dotenv import load_dotenv

openai.api_key = os.getenv("OPENAI_API_KEY")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ChatRequest(BaseModel):
    messages: List[Dict[str, str]]

@app.post("/chat")
async def chat(request: ChatRequest):
    try:
        formatted_messages = []
        
        for msg in request.messages:
            role = "assistant" if msg["role"] == "assistant" else "user"
            formatted_messages.append({"role": role, "content": msg["content"]})
        
        response = openai.chat.completions.create(
            model=os.getenv("OPENAI_DEFAULT_MODEL"),
            messages=formatted_messages
        )
        
        assistant_response = response.choices[0].message.content
        
        return {"response": assistant_response}
    
    except Exception as e:
        print(f"OpenAI API 오류: {str(e)}")
        raise HTTPException(status_code=500, detail=f"AI 응답 생성 중 오류 발생: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)