import base64
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

HOST = "127.0.0.1"
PORT = 54321
BUFFER_SIZE = 4096
MESSAGE = "hello world"

# -------------------- Base64 & File I/O --------------------
def B64Encoding(data: bytes) -> bytes:
    return base64.b64encode(data)

def B64Decoding(b64data: bytes) -> bytes:
    return base64.b64decode(b64data)

def decrypt_message(encrypted_message):
    cipher_aes = AES.new(aes_key, AES.MODE_OFB, iv=iv)
    return cipher_aes.decrypt(encrypted_message).decode()


def receive_messages(connection):
    print("[Server] Receice_message Thread 실행!!!")
    while True:
        try:
            encrypted_message = connection.recv(BUFFER_SIZE)
            if encrypted_message:
                decrypted_message = decrypt_message(encrypted_message)
                print(f"\n[클라이언트 {client_address}] {B64Encoding(encrypted_message)}", flush=True)
                print(f"[클라이언트 {client_address}] {decrypted_message}", flush=True)
                print("서버:", end="", flush=True)
                if decrypted_message.lower() == 'exit':
                    break
        except:
            print("클라이언트 연결이 종료되었습니다.")
            break


def send_messages(connection):
    print("[Server] Send_message Thread 실행!!!")
    while True:
        message = input("서버: ")
        cipher_aes = AES.new(aes_key, AES.MODE_OFB, iv=iv)
        encrypted_message = cipher_aes.encrypt(message.encode())
        connection.send(encrypted_message)
        if message.lower() == 'exit':
            break


if __name__ == '__main__':
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print("[Server] 서버가 클라이언트를 기다리는 중입니다...")

    connection, client_address = server_socket.accept()
    print(f"[Server] {client_address} 클라이언트가 연결되었습니다.")

    # 만일 메시지에 대해서 AES로 암복호화를 해야 한다면... ???
    # 단, AES 암호화 키를 미리 공유해야 한다는 문제점이 발생함
    aes_key = b"0123456789012345"
    print(f"[Server] AES Key {aes_key.decode()}를 사용하여 암복호화 합니다.")
    iv = get_random_bytes(16)  # OFB 모드용 초기화 벡터 생성
    connection.send(iv)
    #client_socket.send(MESSAGE.encode())
    print(f"[Server] 클라이언트로 AES IV {iv}를 전송하였습니다.")

    # 수신 및 전송 스레드 실행
    receive_thread = threading.Thread(target=receive_messages, args=(connection,))
    send_thread = threading.Thread(target=send_messages, args=(connection,))

    receive_thread.start();     send_thread.start()
    receive_thread.join();     send_thread.join()

    connection.close();     server_socket.close()