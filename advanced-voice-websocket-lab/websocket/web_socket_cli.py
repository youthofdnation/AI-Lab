import asyncio
import websockets
import json
import random
import sys
import threading
import queue
import os

user_name = sys.argv[1] if len(sys.argv) > 1 else f"사용자_{random.randint(1000, 9999)}"

message_queue = queue.Queue()

event_loop = None
should_exit = False

def read_input():
    global should_exit
    
    try:
        while not should_exit:
            message = input(f"{user_name}> ")
            if message.lower() == 'exit':
                should_exit = True
                message_queue.put("__exit__")
                break
            
            if message:
                message_queue.put(message)
    except (KeyboardInterrupt, EOFError):
        should_exit = True
        message_queue.put("__exit__")

async def listen_for_messages(websocket):
    global should_exit
    
    try:
        while not should_exit:
            try:
                message = await asyncio.wait_for(websocket.recv(), timeout=0.1)
                print('\r' + ' ' * 50 + '\r', end='')  
                
                try:
                    data = json.loads(message)
                    if isinstance(data, dict) and "time" in data and "message" in data:
                        print(f"[{data['time']}] {data.get('client_id', 'unknown')}: {data['message']}")
                    else:
                        print(f"수신: {message}")
                except json.JSONDecodeError:
                    print(f"수신: {message}")
                
                print(f"{user_name}> ", end='', flush=True)
            except asyncio.TimeoutError:
                continue
            except websockets.exceptions.ConnectionClosed:
                print("\r\n연결이 종료되었습니다.")
                should_exit = True
                break
    except Exception as e:
        print(f"\r\n메시지 수신 중 오류 발생: {e}")
        should_exit = True

async def send_messages(websocket):
    """큐에서 메시지를 가져와 서버로 전송하는 비동기 함수"""
    global should_exit
    
    try:
        while not should_exit:
            try:
                await asyncio.sleep(0.1)
                
                if not message_queue.empty():
                    message = message_queue.get_nowait()
                    
                    if message == "__exit__":
                        should_exit = True
                        break
                    
                    await websocket.send(f"{user_name}: {message}")
            except Exception as e:
                print(f"\r\n메시지 전송 중 오류 발생: {e}")
                should_exit = True
                break
    except Exception as e:
        print(f"\r\n메시지 전송 루프 오류: {e}")
        should_exit = True

async def connect_to_websocket():
    """WebSocket 서버에 연결하고 메시지 송수신을 처리하는 메인 함수"""
    global should_exit
    
    uri = "ws://localhost:8000/ws"
    
    try:
        async with websockets.connect(uri) as websocket:
            print(f"서버에 연결되었습니다: {uri}")
            print(f"채팅을 시작합니다. 종료하려면 'exit'를 입력하세요.")
            print(f"{user_name}> ", end='', flush=True)
            
            input_thread = threading.Thread(target=read_input)
            input_thread.daemon = True
            input_thread.start()
            
            receiver_task = asyncio.create_task(listen_for_messages(websocket))
            sender_task = asyncio.create_task(send_messages(websocket))
            
            while not should_exit:
                await asyncio.sleep(0.1)
            
            receiver_task.cancel()
            sender_task.cancel()
            
    except websockets.exceptions.ConnectionError:
        print(f"서버 연결 실패: {uri}")
        print("서버가 실행 중인지 확인하세요.")
        should_exit = True
    except Exception as e:
        print(f"예상치 못한 오류 발생: {e}")
        should_exit = True

def main():
    """메인 함수"""
    global event_loop, should_exit
    
    try:
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
        
        event_loop.run_until_complete(connect_to_websocket())
    except KeyboardInterrupt:
        print("\r\n프로그램을 종료합니다.")
        should_exit = True
    finally:
        if event_loop:
            event_loop.close()

if __name__ == "__main__":
    main()