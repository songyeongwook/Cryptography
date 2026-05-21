import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

HOST = "127.0.0.1"
PORT = 54321
BUFFER_SIZE = 4096
MESSAGE = "hello world"

def receive_messages():
    print("[Server] Receice_message Thread 실행!!!")


def send_messages():
    print("[Server] Send_message Thread 실행!!!")


if __name__ == '__main__':
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print("[Server] 서버가 클라이언트를 기다리는 중입니다...")

    connection, client_address = server_socket.accept()  # connection --: connection
    print(f"[Server] {client_address} 클라이언트가 연결되었습니다.")

    # 만일 메시지에 대해서 AES로 암복호화를 해야 한다면... ???
    connection.send(MESSAGE.encode())
    print(f"[Server] 클라이언트로 {MESSAGE}를 전송하였습니다.")

    # 수신 및 전송 스레드 실행
    receive_thread = threading.Thread(target=receive_messages)
    send_thread = threading.Thread(target=send_messages)

    receive_thread.start();     send_thread.start()
    receive_thread.join();     send_thread.join()

    connection.close();     server_socket.close()