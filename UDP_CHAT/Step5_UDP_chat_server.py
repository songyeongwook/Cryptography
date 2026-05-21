import socket
import os
import threading

HOST = "127.0.0.1" # 서버 IP 번호
PORT = 50050
BUFFER_SIZE = 4096

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # 서버 UDP 소켓 생성
    sock.bind((HOST, PORT)) # bind 과정 진행
    print(f"[Server] Listening on udp://{HOST}:{PORT}")

    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
        print(f"[Server] Data '{data.decode()}' received from client {addr}")
        # 종료 신호를 받으면 종료
        if data == b"EOF":
            break
    sock.close()
    print("[Server] Connection closed.")

if __name__ == "__main__":
    main()