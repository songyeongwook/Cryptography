import socket
import os
import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 50050
BUFFER_SIZE = 4096
FILE_TO_SEND = "client_public_key.pem"
FILE_RECEIVED = "received_encrypted_data.txt"


def send_public_key(sock, server_addr, public_key):
    """서버로 공개키를 전송합니다."""
    # 공개키를 파일로 저장
    with open(FILE_TO_SEND, 'wb') as f:
        f.write(public_key)

    # (1) 공개키 파일 전송
    print(f"[Client] Sending '{FILE_TO_SEND}' to {SERVER_HOST}:{SERVER_PORT}")
    with open(FILE_TO_SEND, "rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            sock.sendto(chunk, server_addr)
    sock.sendto(b"EOF", server_addr)
    print("[Client] Public key sent. Waiting for server response...")


def generate_rsa_keys():
    """256바이트 RSA 키 쌍(개인키, 공개키)을 생성합니다."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def receive_encrypted_data(sock):
    """서버로부터 암호화된 데이터를 수신하고 파일로 저장합니다."""
    with open(FILE_RECEIVED, "wb") as f:
        while True:
            data, _ = sock.recvfrom(BUFFER_SIZE)
            if data == b"EOF":
                print("[Client] Encrypted data received completely from server.")
                break
            f.write(data)
    print(f"[Client] Received encrypted data saved as '{FILE_RECEIVED}'")


# AES 키를 RSA 개인키로 복호화
def decrypt_aes_key_rsa(encrypted_key, private_key_bytes):
    private_key = RSA.import_key(private_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key

# AES 복호화 (OFB 모드)
def decrypt_aes_ofb(iv, ciphertext, aes_key):
    cipher = AES.new(aes_key, AES.MODE_OFB, iv)
    return cipher.decrypt(ciphertext)

def decrypt_hybrid(encrypted_file, client_private_key_pem):
    # 암호화된 데이터 파일 읽기
    with open(encrypted_file, 'rb') as f:
        # 데이터 구조: [암호화된 AES키(256B) | IV(16B) | 암호화된 메시지]
        enc_aes_key = f.read(256)  # RSA로 암호화된 AES 키
        iv = f.read(16)  # AES OFB 모드의 IV
        ciphertext = f.read()  # 암호화된 메시지

    # 1. RSA 개인키로 AES 키 복호화
    aes_key = decrypt_aes_key_rsa(enc_aes_key, client_private_key_pem)

    # 2. 획득한 AES 키로 메시지 복호화
    plaintext = decrypt_aes_ofb(iv, ciphertext, aes_key)

    return plaintext


if __name__ == "__main__":
    # 1. 클라이언트 RSA 키 쌍 생성
    client_private_key, client_public_key = generate_rsa_keys()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (SERVER_HOST, SERVER_PORT)

    # 2. 서버로 공개키 전송
    send_public_key(sock, server_addr, client_public_key)

    # 3. 서버로부터 암호화된 데이터 수신
    receive_encrypted_data(sock)
    sock.close()

    # 4. 수신된 데이터 복호화 및 원본 메시지 출력
    plaintext = decrypt_hybrid(FILE_RECEIVED, client_private_key)
    print("\n[결과] 복호화된 메시지:", plaintext.decode('utf-8'))