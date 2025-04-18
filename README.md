# AI-Lab

📌 **AI Project Portfolio**  
This repository contains a collection of practical AI projects developed during advanced AI training programs focused on LLMs, RAG, Whisper, Stable Diffusion, and more.

---

## 🔍 About

This portfolio includes hands-on projects built while attending:

- **Generative AI Practical Application Masterclass (2025.03 – 2025.05)**
- **Intermediate AI Course – RAG & GPT (2024.09 – 2024.10)**
- **AI Core Technology Intensive Course (2024.07 – 2024.09)**

The projects are focused on real-world applications of LLMs, multimodal AI, and deployment-ready features.

---

## 🧠 Core AI Projects (LLMs, Agents, Diffusion)

| Project | Description | Tech Stack |
|--------|-------------|------------|
| [`rag-chatbot`](./rag-chatbot) | LLM-based chatbot with RAG + document search using Vector DB | Python, LangChain, FAISS, Hugging Face |
| [`whisper-voicebot`](./whisper-voicebot) | Voice-enabled chatbot using Whisper and OpenAI | Python, Whisper, FastAPI |
| [`image-gen`](./image-gen) | Stable Diffusion-based image generation service | Stable Diffusion, Gradio |
| [`code-assistant`](./code-assistant) | LLM-powered code generation & explanation tool | Python, OpenAI API |
| [`ai-agent-lab`](./ai-agent-lab) | Custom AI Agent framework for multi-tasking | Python, LangGraph |

> ⚠️ Project folders & README will be continuously updated.

---

## 🧪 Interactive LLM Apps (Streamlit & Gradio)

| File | Description |
|------|-------------|
| `text.py`, `ui_component.py` | Streamlit UI elements (text input, selectors, layout) |
| `data.py`, `graph.py` | Streamlit data visualization and display logic |
| `session.py` | Session state & reactive logic example |
| `gradio_single_chat.py` | Single-user LLM chatbot using Gradio |
| `gradio_multi_chat.py` | Multi-turn chatbot using Gradio framework |
| `gradio_chatbot.ipynb` | Notebook-based chatbot with Gradio interface |

**Tech Stack:** Python, Streamlit, Gradio, OpenAI API, seaborn, scikit-learn

---

## 🤖 OpenAI Chatbot Lab

| File | Description |
|------|-------------|
| `1. oai_basic.ipynb` | Basic OpenAI API usage example |
| `2. examples.ipynb` | Prompt examples and usage variations |
| `3. prompt engineering.ipynb` | Prompt tuning & engineering best practices |
| `streamlit_multi_chat.py` | Streamlit-based multi-turn chatbot using GPT |

**Tech Stack:** Python, OpenAI API, Streamlit

---

## 🗣️ Voice + Web Interaction Lab

This section showcases real-time voice AI integration with web technologies like HTML5, FastAPI, WebSocket, and Streamlit.

| Folder / File | Description | Tech Stack |
|---------------|-------------|------------|
| `notebooks/whisper.ipynb` | Speech-to-Text using OpenAI Whisper | Python, Whisper, Jupyter |
| `notebooks/pyttsx3.ipynb` | Text-to-Speech (offline, system voice) | Python, pyttsx3 |
| `notebooks/gTTS.ipynb` | Text-to-Speech using Google TTS | Python, gTTS |
| `html/1. audio.html` | Browser-based voice recording & playback UI | HTML, JavaScript |
| `html/2. camera.html` | Webcam stream interface (browser-based) | HTML, JavaScript |
| `html/3. audio_stt_realtime.html` | Real-time voice recording → STT conversion | HTML, JS, WebSocket |
| `html/4. tts.html` | Text input → TTS output via API | HTML, JS, FastAPI |
| `fastapi/get_example.py` | FastAPI GET request example | Python, FastAPI |
| `fastapi/post_example.py` | FastAPI POST (TTS) API endpoint | Python, FastAPI |
| `fastapi/websocket_example.py` | WebSocket server for real-time audio | Python, FastAPI, WebSocket |
| `websocket/simple_ws.py` | WebSocket client test script | Python, WebSocket |
| `streamlit/streamlit_multi_chat.py` | Streamlit UI for multi-turn chat (TTS/STT) | Python, Streamlit |
| `tts_audio/OMG.mp3` | Sample audio file (generated speech) | MP3 |

**Tech Stack:** Python, FastAPI, Streamlit, WebSocket, gTTS, pyttsx3, Whisper, HTML5, JavaScript

---

## 🌐 Real-Time WebSocket & Chat Lab 
This lab focuses on real-time web communication using WebSocket protocol, FastAPI server, and Streamlit-based multi-turn chatbot.

| Folder / File | Description | Tech Stack |
|---------------|-------------|------------|
| `fastapi/websocket_example.py` | FastAPI WebSocket server for real-time messaging | Python, FastAPI, WebSocket |
| `websocket/simple_ws.py` | WebSocket client for sending/receiving messages | Python, websockets, asyncio |
| `streamlit/streamlit_multi_chat.py` | Streamlit multi-turn chatbot with OpenAI GPT | Python, Streamlit, OpenAI API |
| `run.sh` | Simple HTTP server to serve static files | Shell, Python HTTP Server |

**Tech Stack:** Python, FastAPI, WebSocket, Streamlit, OpenAI API

---

## 🌟 Advanced Voice + WebSocket Chat System

This is an advanced real-time voice recognition and chat system, integrating FastAPI, WebSocket, and Whisper for voice recognition, and frontend technologies for user-friendly web UI. 🎤🗨️

| Folder / File | Description | Tech Stack |
|---------------|-------------|------------|
| `backend.py` | FastAPI server handling WebSocket audio stream and Whisper speech recognition | Python, FastAPI, Whisper |
| `frontend.html` | Main frontend UI for real-time voice recognition & chat (microphone input, visualization, text-to-speech) | HTML, JavaScript, Web Audio API |
| `web_socket.html` | Simple WebSocket text chat client | HTML, JavaScript |
| `web_socket_cli.py` | Command-line WebSocket client for real-time text chat | Python, asyncio, websockets |
| `install.sh` | Environment setup script (install dependencies) | Bash, pip |
| `.env` | Environment variables (OpenAI API Key etc.) | - |

**Tech Stack:**  
Python, FastAPI, WebSocket, Whisper, HTML5, JavaScript, AudioContext API, Web Speech API, asyncio, pydub, soundfile, librosa

**Features:**
- 🎙️ Real-time speech-to-text from browser microphone
- 🔁 3-second audio streaming loop to server
- 💬 FastAPI WebSocket server to process audio and return recognized text
- 🖥️ Clean web frontend with audio visualizer
- 🧩 Chat history and typing indicator
- 🧑‍💻 Command-line WebSocket client support
- ✅ Easy installation with `install.sh`

> ⚠️ *Note:* Make sure you run the FastAPI server before opening the frontend page.

**Usage**
1. Run the backend server:
   ```bash
   uvicorn backend:app --reload --host 0.0.0.0 --port 8000

---

## 📄 AI Document Assistant Lab

AI가 PDF 문서를 읽고, 그 내용에 기반해 질문에 답변하는 시스템입니다. LangChain, Sentence Transformers, OpenAI API를 활용하여 업로드된 문서 기반 컨텍스트 Q&A 기능을 구현합니다.

| Folder / File | Description | Tech Stack |
|---------------|-------------|------------|
| `1. langchain.ipynb` | LangChain 기초 사용법, 체인 및 에이전트 구축 실습 | Python, LangChain, OpenAI API |
| `2. LCEL.ipynb` | LangChain Expression Language (LCEL) 실습 노트북 | Python, LangChain |
| `ask_pdf.ipynb` | 업로드된 PDF 문서 기반 AI Q&A 시스템 | Python, LangChain, Sentence Transformers, OpenAI API |
| `소나기.pdf` | 샘플 문서 (황순원의 단편 소설 '소나기') | PDF |

**Tech Stack:**  
Python, LangChain, Sentence Transformers, FAISS, OpenAI API, Jupyter Notebook

**Features:**
- 📄 PDF 업로드 후 전체 텍스트 추출
- 🧩 문장 임베딩 기반 유사도 검색 (Sentence Transformers 사용)
- 💬 문서 기반 문맥 질문 응답
- 🖥️ Jupyter 노트북으로 손쉬운 실습

---

### 📂 RAG 기반 PDF Q&A Web App 확장

업로드된 PDF로부터 벡터 임베딩을 생성하고, 이를 기반으로 실시간 질의응답이 가능한 웹 애플리케이션을 개발했습니다. Gradio 및 Streamlit을 활용한 두 가지 UI 버전을 제공합니다.

| File | Description | Tech Stack |
|------|-------------|------------|
| `ingest.py` | PDF를 로드하고 텍스트 분할 후 FAISS 벡터 저장소 구축 | Python, LangChain, FAISS |
| `ask_pdf.py` | Gradio 기반 챗봇 UI, 실시간 RAG 질의응답 구현 | Python, Gradio, OpenAI API |
| `streamlit_rag.py` | Streamlit 기반 챗봇 UI, 세션 기반 대화 기록 관리 | Python, Streamlit, OpenAI API |

**Features:**
- 📄 PDF 문서 텍스트를 자동 추출 및 분할
- 🔎 임베딩 기반 유사도 검색을 통한 문맥 추출
- 💬 GPT-4o-mini 모델 기반 스트리밍 응답
- 🧑‍💻 Gradio / Streamlit UI 모두 지원

---

## 📦 Real-World Data Automation Projects

| Project | Description | Tech Stack |
|--------|-------------|------------|
| `camping-data` | Scrape and parse camping site data from Korean public OpenAPI | Python, Requests, XML |
| `finance-data` | Retrieve and analyze stock data using PyKRX | Python, PyKRX |
| `kakao-location` | Use Kakao REST API to search local place data | Python, Kakao API |
| `nvidia-model-test` | OpenAI API environment configuration and testing | Python, OpenAI API |

---

## ✨ Skills & Tools

- **LLM**: GPT, RAG, LoRA Fine-tuning  
- **Vision**: Stable Diffusion, OpenCV  
- **Speech**: Whisper, gTTS, pyttsx3  
- **Web**: Streamlit, Gradio, FastAPI, WebSocket, HTML5  
- **Frameworks**: LangChain, Hugging Face Transformers  
- **Infra/ETC**: Git, Python, Jupyter, Google Colab

---

## 📫 Contact

> Created & maintained by [Y]  
> 🔗 [LinkedIn](#) | ✉️ licesneyoo@nate.com
