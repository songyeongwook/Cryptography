import socket
import threading
from Crypto.Cipher import AES

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 54321
BUFFER_SIZE = 4096


def receive_messages():
    print("[Client] Receice_message Thread 실행!!!")


def send_messages():
    print("[Client] Send_message Thread 실행!!!")


if __name__ == '__main__':
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print(f"[Client] 서버 {SERVER_HOST}:{SERVER_PORT}에 연결되었습니다.")

    # 만일 메시지에 대해서 AES로 암복호화를 해야 한다면... ???
    MESSAGE = client_socket.recv(BUFFER_SIZE)
    print(f"[Client] 서버로부터 {MESSAGE.decode()}를 전송 받았습니다.")

    # 수신 및 전송 스레드 실행
    receive_thread = threading.Thread(target=receive_messages)
    send_thread = threading.Thread(target=send_messages)

    receive_thread.start();     send_thread.start()
    receive_thread.join();     send_thread.join()

    client_socket.close()
