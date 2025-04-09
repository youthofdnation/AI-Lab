import io
import numpy as np
import torch
import whisper
import librosa
import soundfile as sf
from pydub import AudioSegment
from fastapi import FastAPI, WebSocket

app = FastAPI()
model = whisper.load_model("medium")  # Whisper 모델 로드

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    print("INFO: connection open")

    try:
        while True:
            audio_data = await websocket.receive_bytes()
            print(f"Received audio chunk: {len(audio_data)} bytes")
            if not audio_data:
                continue

            try:
                audio_stream = io.BytesIO(audio_data)
                audio_stream.seek(0)
                
                try:
                    audio_segment = AudioSegment.from_file(audio_stream)
                    audio_segment = audio_segment.set_channels(1)  # 모노로 변환
                    
                    wav_io = io.BytesIO()
                    audio_segment.export(wav_io, format="wav")
                    wav_io.seek(0)
                    
                    audio, sr = sf.read(wav_io)
                    
                except Exception as format_error:
                    print(f"Audio format conversion error: {format_error}")
                    import wave
                    wav_io = io.BytesIO()
                    with wave.open(wav_io, 'wb') as wf:
                        wf.setnchannels(1)
                        wf.setsampwidth(2)  # 16-bit
                        wf.setframerate(16000)
                        wf.writeframes(audio_data)
                    wav_io.seek(0)
                    audio, sr = sf.read(wav_io)

                if sr != 16000:
                    audio = librosa.resample(audio, orig_sr=sr, target_sr=16000)

                if audio.dtype != np.float32:
                    audio = audio.astype(np.float32)
                
                if len(audio.shape) > 1 and audio.shape[1] > 1:
                    audio = np.mean(audio, axis=1)

                audio = whisper.pad_or_trim(audio)  # 길이 조정
                mel = whisper.log_mel_spectrogram(audio).to(model.device)

                options = whisper.DecodingOptions(
                    language="ko",      # 한국어 설정
                    fp16=torch.cuda.is_available(),
                    task="transcribe"   
                )
                
                result = whisper.decode(model, mel, options)

                print(f"한국어 인식 결과: {result.text}")
                await websocket.send_text(result.text)

            except Exception as e:
                print(f"Transcription Error: {e}")
                await websocket.send_text("음성 인식 오류가 발생했습니다")

    except Exception as e:
        print(f"WebSocket Error: {e}")
    
    finally:
        print("INFO: connection closed")
        await websocket.close()
