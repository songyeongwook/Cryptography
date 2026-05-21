import base64
import socket
import threading

HOST = "127.0.0.1" # 서버 IP 번호
PORT = 50060
BUFFER_SIZE = 4096

# 전역 변수 (마지막으로 메시지를 보낸 클라이언트 주소)
client_addr = None

def receive_messages(sock):
    print("[Server] Receice_message Thread 실행!!!")
    global client_addr
    while True:
        try:
            message, addr = sock.recvfrom(BUFFER_SIZE)
            client_addr = addr # 마지막 클라이언트 주소 저장
            msg_text = message.decode("utf-8", "ignore")
            print(f"\n[클라이언트 {addr}] {msg_text}")
            print("서버:", end="", flush=True)

            if msg_text.lower() == 'exit':
                print("클라이언트가 'exit'를 입력하여 연결 종료.")
                break
        except Exception as e:
            print(f"[Server] 예외 발생: {e}")
            break


def send_messages(sock):
    global client_addr
    print("[Server] Send_message Thread 실행!!!")
    while True:
        if client_addr is None:
            continue  # 클라이언트 접속 전엔 대기
        message = input("서버:")
        sock.sendto(message.encode(), client_addr)
        if message.lower() == 'exit':
            print("exit 입력 : 서버 연결이 강제로 종료되었습니다.")
            break

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"[Server] UDP Chat 서버 실행 중... ({HOST}:{PORT})")

    receive_thread = threading.Thread(target=receive_messages, args=(sock,))
    send_thread = threading.Thread(target=send_messages, args=(sock,))

    receive_thread.start()
    send_thread.start()
    receive_thread.join()
    send_thread.join()
    sock.close()
    print("[Server] 종료되었습니다.")

if __name__ == "__main__":
    main()