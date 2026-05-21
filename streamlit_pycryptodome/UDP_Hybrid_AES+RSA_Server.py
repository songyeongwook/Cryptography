import socket

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

HOST = "0.0.0.0"
PORT = 50050
BUFFER_SIZE = 4096
RECEIVED_FILE = "received_public_key.pem"
MESSAGE = "202155011/소프트웨어융합학부/송영욱/Hybrid AES+RSA UDP Example"

# AES 암호화 (OFB 모드)
def encrypt_aes_ofb(data, aes_key):
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(data)
    return iv, ciphertext

# AES 키를 RSA 공개키로 암호화
def encrypt_aes_key_rsa(aes_key, public_key_bytes):
    public_key = RSA.import_key(public_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"[Server] Listening on udp://{HOST}:{PORT}")

    # 클라이언트의 공개키 수신
    with open(RECEIVED_FILE, "wb") as f:
        print("[Server] Waiting for public key from client...")
        while True:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            if data == b"EOF":
                print(f"[Server] Public key received from {addr}")
                break
            f.write(data)

    # 클라이언트 공개키 로드
    with open(RECEIVED_FILE, "rb") as f:
        client_public_key_pem = f.read()

    # 하이브리드 암호화
    # 1. 랜덤 AES 키 생성
    aes_key = get_random_bytes(32)  # 32 bytes = 256 bits

    # 2. AES-OFB로 메시지 암호화
    iv, ciphertext = encrypt_aes_ofb(MESSAGE.encode(), aes_key)

    # 3. RSA로 AES 키 암호화
    encrypted_aes_key = encrypt_aes_key_rsa(aes_key, client_public_key_pem)

    # 4. 암호화된 데이터 병합: [암호화된 AES키 | IV | 암호화된 메시지]
    # RSA 2048bit 키로 암호화된 AES 키는 256바이트
    # OFB 모드의 IV는 16바이트
    payload = encrypted_aes_key + iv + ciphertext

    # 클라이언트로 암호화된 데이터 전송
    print(f"[Server] Sending encrypted data back to client...")
    sock.sendto(payload, addr)
    sock.sendto(b"EOF", addr)

    print("[Server] Encrypted data sent back to client successfully.")
    sock.close()


if __name__ == "__main__":
    main()