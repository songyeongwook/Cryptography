import socket
import os

HOST = "127.0.0.1" # 서버 IP 번호
PORT = 50050
BUFFER_SIZE = 4096
OUTPUT_FILE = "Readme-received.txt" # 수신한 파일에 대해서 저장할 이름 지정

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # 서버 UDP 소켓 생성
    sock.bind((HOST, PORT)) # bind 과정 진행
    print(f"[Server] Listening on udp://{HOST}:{PORT}")

    with open(OUTPUT_FILE, "wb") as f:
        while True:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            # 종료 신호를 받으면 종료
            if data == b"EOF":
                print(f"[Server] File transfer complete from {addr}")
                print(f"[Server] Saving to '{OUTPUT_FILE}'")
                break
            f.write(data)

    ### 만일 클라이언트에서 서버로 파일을 다시 전송하기 위해서는 여기에 코드 작성하면 됨

    sock.close()
    print("[Server] File saved and connection closed.")


if __name__ == "__main__":
    main()