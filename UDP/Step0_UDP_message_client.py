import socket
import os

SERVER_HOST = "127.0.0.1"   # 서버 주소
SERVER_PORT = 50050 # 서버 포트번호
BUFFER_SIZE = 4096

MESSAGE = "Hello World"
EOF = b"EOF"

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP socket 생성
    server_addr = (SERVER_HOST, SERVER_PORT) # 서버 접속 주소/포트 번호 구성
    sock.sendto(MESSAGE.encode(), server_addr) # 소켓을 이용하여 전송
    print(f"[Client] Message '{MESSAGE}' sent successfully to {SERVER_HOST}:{SERVER_PORT}")

    # 전송 종료 신호
    sock.sendto(EOF.encode(), server_addr)
    sock.close()
    print(f"[Client] Message '{EOF}' sent successfully to {SERVER_HOST}:{SERVER_PORT}")

if __name__ == "__main__":
    main()