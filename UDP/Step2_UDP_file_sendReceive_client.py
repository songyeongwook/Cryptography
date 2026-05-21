#!/usr/bin/env python3
import socket
import os

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 50050
BUFFER_SIZE = 4096
FILE_TO_SEND = "../Practice/Readme.txt"
FILE_RECEIVED = "returned.txt"

def main():
    if not os.path.exists(FILE_TO_SEND):
        print(f"[Client] File '{FILE_TO_SEND}' not found.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (SERVER_HOST, SERVER_PORT)

    # (1) 파일 전송
    print(f"[Client] Sending '{FILE_TO_SEND}' to {SERVER_HOST}:{SERVER_PORT}")
    with open(FILE_TO_SEND, "rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            sock.sendto(chunk, server_addr)
    sock.sendto(b"EOF", server_addr)
    print("[Client] File sent. Waiting for server response...")

    # (2) 서버로부터 파일 수신
    with open(FILE_RECEIVED, "wb") as f:
        while True:
            data, _ = sock.recvfrom(BUFFER_SIZE)
            if data == b"EOF":
                print("[Client] File received completely from server.")
                break
            f.write(data)

    sock.close()
    print(f"[Client] Received file saved as '{FILE_RECEIVED}'")

if __name__ == "__main__":
    main()