import socket
import os

SERVER_HOST = "127.0.0.1"   # 서버 주소
SERVER_PORT = 50050 # 서버 포트번호
BUFFER_SIZE = 4096 # 버퍼 크기
FILE_PATH = "../Practice/Readme.txt"  # 전송하고자 하는 파일명

def main():
    ## step 1
    if not os.path.exists(FILE_PATH): # 파일 존재 유무 체크
        print(f"[Client] File '{FILE_PATH}' not found.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP socket 생성
    server_addr = (SERVER_HOST, SERVER_PORT) # 서버 접속 주소/포트 번호 구성

    with open(FILE_PATH, "rb") as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            sock.sendto(chunk, server_addr) # 소켓을 이용하여 전송
    # 파일 전송 종료 신호
    sock.sendto(b"EOF", server_addr)

    # 만일 서버로 부터 파일을 받기 위해서는 여기에 코드 추가하면 됨
    sock.close()
    print(f"[Client] File '{FILE_PATH}' sent successfully to {SERVER_HOST}:{SERVER_PORT}")


if __name__ == "__main__":
    main()