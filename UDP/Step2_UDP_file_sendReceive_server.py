#!/usr/bin/env python3
import socket

HOST = "0.0.0.0"
PORT = 50050
BUFFER_SIZE = 4096
RECEIVED_FILE = "Readme-received.txt"

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"[Server] Listening on udp://{HOST}:{PORT}")

    with open(RECEIVED_FILE, "wb") as f:
        print("[Server] Waiting for file data from client...")
        while True:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            if data == b"EOF":
                print(f"[Server] File received from {addr}")
                break
            f.write(data)

    # 클라이언트로 다시 파일 전송
    print(f"[Server] Sending file '{RECEIVED_FILE}' back to client...")
    with open(RECEIVED_FILE, "rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            sock.sendto(chunk, addr)
    sock.sendto(b"EOF", addr)

    print("[Server] File sent back to client successfully.")
    sock.close()

if __name__ == "__main__":
    main()