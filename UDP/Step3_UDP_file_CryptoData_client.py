#!/usr/bin/env python3
import base64
import socket
import os

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 50050
BUFFER_SIZE = 4096
FILE_TO_SEND = "client_public_key.pem"
FILE_RECEIVED = "return_b64encoded_ciphertext.txt"


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


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def decryptFile(FILE_RECEIVED, client_private_key):
    ciphertext = readFromFile(FILE_RECEIVED)
    private_key = RSA.importKey(client_private_key)
    rsa = PKCS1_OAEP.new(private_key)
    plaintext = rsa.decrypt(ciphertext)
    return plaintext


if __name__ == "__main__":
    # client
    # Step 1 : client의 privateKey, publicKey 생성
    # Step 2 : client는 자신의 publicKey 파일을 서버로 전송함
    # Step 3 : client는 서버로 부터 암호화된 파일을 받음
    # Step 4 : client는 서버로 부터 받은 파일에 대해 cliwent의 privateKey를 이용하여 복호화 함

    # Step 1 : client의 privateKey, publicKey 생성
    client_private_key, client_public_key = generate_rsa_keys()
    with open(FILE_TO_SEND, 'wb') as f:
        f.write(bytes(client_private_key))

    # Step 2 : client는 자신의 publicKey 파일을 서버로 전송함
    # Step 3 : client는 서버로 부터 암호화된 파일을 받음
    main()

    # Step 4 : client는 서버로 부터 받은 파일에 대해 cliwent의 privateKey를 이용하여 복호화 함
    plaintext = decryptFile(FILE_RECEIVED, client_private_key)
    print("수신된 메시지:", plaintext.decode())

    #KEY(랜덤으로 생성후)를 RSA로 암호화 해서 하나의 파일로 붙여서  서버에 넘겨준다.