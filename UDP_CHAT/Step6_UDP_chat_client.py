import base64
import socket
import threading

SERVER_HOST = "127.0.0.1"   # 서버 주소
SERVER_PORT = 50060
BUFFER_SIZE = 4096


def receive_messages(sock):
    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            print(f"\n[서버 {addr}] {data.decode()}")
            print("클라이언트:", end="", flush=True)  # input()과 print() 간섭 줄이기 위해 flush=True 사용
        except:
            break


if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (SERVER_HOST, SERVER_PORT)  # 서버 접속 주소/포트 번호 구성
    print(f"[Client] UDP Chat 서버 ({SERVER_HOST}:{SERVER_PORT}) 에 접속하였음...")

    # UDP는 비연결형이라, 클라이언트가 단순히 input()으로 입력받아 보내면 됨
    # 즉, 아래처럼 메인 스레드가 송신을 담당하고, 수신은 별도 스레드에서 처리하면 충분
    # 즉, 메인 스레드가 send 역할을 직접 수행하고 있어서
    # 별도의 send_thread = threading.Thread(target=send_messages, args=(sock,))가 필요하지 않음
    receive_thread = threading.Thread(target=receive_messages, args=(sock,))
    receive_thread.start()

    while True:
        msg = input("클라이언트:")
        sock.sendto(msg.encode(), (SERVER_HOST, SERVER_PORT))
        if msg.lower() == "exit":
            break
    sock.close()
    print("[Client] 종료되었습니다.")