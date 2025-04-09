#!/bin/bash
sudo apt-get update
sudo apt-get install python3 python3-pip uvicorn ffmpeg -y
pip install numpy torch openai-whisper librosa soundfile pydub fastapi uvicorn websockets

