import base64
import socket
import threading
from Crypto.Cipher import AES

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 54321
BUFFER_SIZE = 4096

# -------------------- Base64 & File I/O --------------------
def B64Encoding(data: bytes) -> bytes:
    return base64.b64encode(data)

def B64Decoding(b64data: bytes) -> bytes:
    return base64.b64decode(b64data)


def decrypt_message(encrypted_message):
    cipher_aes = AES.new(aes_key, AES.MODE_OFB, iv=iv)
    return cipher_aes.decrypt(encrypted_message).decode()


def receive_messages(client_socket):
    print("[Client] Receice_message Thread 실행!!!")
    while True:
        try:
            encrypted_message = client_socket.recv(BUFFER_SIZE)
            if encrypted_message:
                decrypted_message = decrypt_message(encrypted_message)
                print(f"\n[서버 {server_addr}] {B64Encoding(encrypted_message)}", flush=True)
                print(f"[서버 {server_addr}] {decrypted_message}", flush=True)
                print("클라이언트:", end="", flush=True) # input()과 print() 간섭 줄이기 위해 flush=True 사용
                if decrypted_message.lower() == 'exit':
                    break
        except:
            print("서버 연결이 종료되었습니다.")
            break



def send_messages(client_socket):
    print("[Client] Send_message Thread 실행!!!")
    while True:
        message = input("클라이언트: ")
        cipher_aes = AES.new(aes_key, AES.MODE_OFB, iv=iv)
        encrypted_message = cipher_aes.encrypt(message.encode())
        client_socket.send(encrypted_message)
        if message.lower() == 'exit':
            break

if __name__ == '__main__':
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_addr = (SERVER_HOST, SERVER_PORT)  # 서버 접속 주소/포트 번호 구성
    client_socket.connect(server_addr)
    print(f"[Client] 서버 {server_addr}에 연결되었습니다.")

    # 만일 메시지에 대해서 AES로 암복호화를 해야 한다면... ???
    # 단, AES 암호화 키를 미리 공유해야 한다는 문제점이 발생함
    aes_key = b"0123456789012345"
    print(f"[Client] AES Key {aes_key.decode()}를 사용하여 암복호화 합니다.")
    #MESSAGE = client_socket.recv(BUFFER_SIZE)
    iv = client_socket.recv(16)
    print(f"[Client] 서버로부터 AES IV 값 {iv}를 전송 받았습니다.")

    # 수신 및 전송 스레드 실행
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    send_thread = threading.Thread(target=send_messages, args=(client_socket,))

    receive_thread.start();     send_thread.start()
    receive_thread.join();     send_thread.join()

    client_socket.close()
