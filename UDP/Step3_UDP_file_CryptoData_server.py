#!/usr/bin/env python3
import base64
import socket

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


HOST = "0.0.0.0"
PORT = 50050
BUFFER_SIZE = 4096
RECEIVED_FILE = "received_client_public_key.pem"
CIPHERTEXT_FILE = "b64encoded_ciphertext.txt"
MESSAGE = "Hello World 한신대학교 AISW대학 보안프로그래밍"

# -------------------- Base64 & File I/O --------------------
def B64Encoding(data: bytes) -> bytes:
    return base64.b64encode(data)

def B64Decoding(b64data: bytes) -> bytes:
    return base64.b64decode(b64data)

def writeToFile(filename: str, data: bytes) -> None:
    with open(filename, "wb") as f:
        f.write(B64Encoding(data))

def readFromFile(filename: str) -> bytes:
    with open(filename, "rb") as f:
        raw = f.read()
    return B64Decoding(raw)

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

    # encryptFile 생성 : RSA 암호화 과정을 진행, 파일로 생성
    with open(RECEIVED_FILE, "rb") as f:
        client_public_key_pem = f.read()
    client_public_key = RSA.importKey(client_public_key_pem)
    rsa = PKCS1_OAEP.new(client_public_key)
    ciphertext = rsa.encrypt(MESSAGE.encode())
    writeToFile(CIPHERTEXT_FILE, ciphertext)

    # 클라이언트로 다시 파일 전송
    print(f"[Server] Sending file '{CIPHERTEXT_FILE}' back to client...")
    with open(CIPHERTEXT_FILE, "rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            sock.sendto(chunk, addr)
    sock.sendto(b"EOF", addr)

    print("[Server] File sent back to client successfully.")
    sock.close()

if __name__ == "__main__":
    # server
    # server는 클라이언트의 publicKey를 받음
    # server는 클라이언트의 publicKey를 이용하여 메시지를 암호화 함
    # 그리고 server는 클라이언트로 암호화된 메시지를 전송함
    main()