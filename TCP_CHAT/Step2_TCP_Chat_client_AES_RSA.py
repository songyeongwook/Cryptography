import base64
import binascii
import socket
import threading
import time

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, PKCS1_v1_5

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 54321
BUFFER_SIZE = 4096

CLIENT_PRIVATE_KEY =  "./Client/client_private_key.pem"
CLIENT_PUBLIC_KEY = "./Client/client_public_key.pem"
SERVER_PUBLIC_KEY = "./Client/server_public_key.pem"

# -------------------- Base64 & File I/O --------------------
def B64Encoding(data: bytes) -> bytes:
    return base64.b64encode(data)

def B64Decoding(b64data: bytes) -> bytes:
    return base64.b64decode(b64data)


def decrypt_message(encrypted_message):
    cipher_aes = AES.new(aes_key, AES.MODE_OFB, iv=iv)
    return cipher_aes.decrypt(encrypted_message).decode()



def dec_ciphertext_sessionkey_alice(sessionkey_enc, ciphertext):
    with open(CLIENT_PRIVATE_KEY, 'rb') as f:
        client_private_key = RSA.importKey(f.read())
    rsa_obj = PKCS1_OAEP.new(client_private_key)
    sessionkey_dec = rsa_obj.decrypt(sessionkey_enc)
    iv = ciphertext[:16]
    aes_obj = AES.new(sessionkey_dec, AES.MODE_CFB, iv)
    plaintext_with_sign_dec = aes_obj.decrypt(ciphertext[16:])
    return plaintext_with_sign_dec


def seperate_and_verify_sign_alice(plaintext_with_sign_dec):
    signature = plaintext_with_sign_dec[:256]
    plaintext = plaintext_with_sign_dec[256:]
    server_public_key = RSA.importKey(open(SERVER_PUBLIC_KEY, 'rb').read())
    hash_obj = SHA512.new(plaintext)

    try:
        pkcs1_15.new(server_public_key).verify(hash_obj, signature)
        print("HybridCrypto & Signature Verification Result : True")
        return plaintext.decode()   ## 추가
    except (ValueError, TypeError):
        print("Signature Verification Result : False")
        return "Error on Verification!!!"


def receive_messages(client_socket):
    print("[Client] Receice_message Thread 실행!!!")
    while True:
        try:
            encrypted_message = client_socket.recv(BUFFER_SIZE)
            if encrypted_message:
                # 아래 코드 대신에 수정
               #decrypted_message = decrypt_message(encrypted_message)
                sessionkey_enc_hex, ciphertext_hex = encrypted_message.split(b'***===***')
                sessionkey_enc = binascii.unhexlify(sessionkey_enc_hex)
                ciphertext = binascii.unhexlify(ciphertext_hex)
                # 세션키와 암호문을 이용한 복호화
                plaintext_with_sign_dec = dec_ciphertext_sessionkey_alice(sessionkey_enc, ciphertext)
                # 전자서명 분리 및 검증
                decrypted_message = seperate_and_verify_sign_alice(plaintext_with_sign_dec)  ##     변경
                print(f"\n[서버 {server_addr}] {B64Encoding(encrypted_message)}", flush=True)
                print(f"[서버 {server_addr}] {decrypted_message}", flush=True)
                print("클라이언트:", end="", flush=True) # input()과 print() 간섭 줄이기 위해 flush=True 사용
                if decrypted_message.lower() == 'exit':
                    break
        except:
            print("서버 연결이 종료되었습니다.")
            break


def gen_client_signature(plaintext):   ## 함수 이름 변경 gen_signature --> gen_alice_signature
        client_privatekey = RSA.importKey(open(CLIENT_PRIVATE_KEY, 'rb').read())
        plaintext_hash = SHA512.new(plaintext)
        signature_obj = PKCS1_v1_5.new(client_privatekey)
        signature = signature_obj.sign(plaintext_hash)
        return signature + plaintext

def gen_client_AES_ciphertext(sign_plaintext): ## 함수 이름 변경 gen_AES_ciphertext --> gen_alice_AES_ciphertext
    ### 밥의 공개키로 세션키 암호화
    sessionkey = Random.new().read(32)  # 32 bytes -> 256 bit
    server_publickey = RSA.importKey(open(SERVER_PUBLIC_KEY, 'rb').read())
    rsa_obj = PKCS1_OAEP.new(server_publickey)
    sessionkey_enc = rsa_obj.encrypt(sessionkey)
    iv = Random.new().read(16)  # 16 bytes -> 128 bit
    aes_obj = AES.new(sessionkey, AES.MODE_CFB, iv)  # CFB 모드로 암호화
    ciphertext = iv + aes_obj.encrypt(sign_plaintext)
    return (sessionkey_enc, ciphertext)


def gen_client_output(sessionkey_enc, ciphertext):    ## 함수 이름 변경 gen_output --> gen_Alice_output
    output = (binascii.hexlify(sessionkey_enc)
              + "***===***".encode('utf-8')
              + binascii.hexlify(ciphertext))
    return output


def send_messages(client_socket):
    print("[Client] Send_message Thread 실행!!!")
    while True:
        message = input("클라이언트: ")
        # 아래 코드 대신에 수정...
        #cipher_aes = AES.new(aes_key, AES.MODE_OFB, iv=iv)
        #encrypted_message = cipher_aes.encrypt(message.encode())
        # Alice의 개인키로 전자서명 생성 후 평문과 연결
        sign_plaintext = gen_client_signature(message.encode())
        # 세션키 생성 후 AES 암호화 -> Bob의 공개키로 세션키 암호화
        sessionkey_enc, ciphertext = gen_client_AES_ciphertext(sign_plaintext)
        # Bob에게 전송할 메시지 생성 및 전송
        encrypted_message = gen_client_output(sessionkey_enc, ciphertext)
        client_socket.send(encrypted_message)
        if message.lower() == 'exit':
            break


def gen_client_key():
    key = RSA.generate(bits=2048)  # RSA의 키 길이는 2048 bits
    client_private_key = key.export_key(format='PEM')  # 'PEM' 방식은 Base64로 인코딩된 텍스트 기반의 인코딩 방식
    client_public_key = key.publickey().export_key(format='PEM')
    with open(CLIENT_PRIVATE_KEY, 'wb') as f:
        f.write(bytes(client_private_key))
    with open(CLIENT_PUBLIC_KEY, 'wb') as f:
        f.write(bytes(client_public_key))
    return (client_private_key, client_public_key)


# 공개키 공유 스레드
def keySharing_client():
    # Alice의 키 생성
    client_private_key, client_public_key = gen_client_key()
    # Alice의 공개키 전송 및 Bob의 공개키 수신
    print('Client의 공개키를 Server로 전송합니다.')
    client_socket.send(client_public_key)
    print("Waiting for Server's public key...")
    server_public_key = client_socket.recv(2048)
    if not server_public_key:
        print('Server의 공개키를 받지 못했습니다.')
        return
    # Bob의 공개키 저장
    print(f"Received public key from Server : {client_socket.getpeername()[0], client_socket.getpeername()[1]}")
    with open(SERVER_PUBLIC_KEY, 'wb') as f:
        f.write(server_public_key)


if __name__ == '__main__':
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_addr = (SERVER_HOST, SERVER_PORT)  # 서버 접속 주소/포트 번호 구성
    client_socket.connect(server_addr)
    print(f"[Client] 서버 {server_addr}에 연결되었습니다.")

    # AES 키를 공유하는 부분을 RSA 기반 키 전송 구조로 변경

    # 만일 메시지에 대해서 AES로 암복호화를 해야 한다면... ???
    # 단, AES 암호화 키를 미리 공유해야 한다는 문제점이 발생함
    aes_key = b"0123456789012345"
    print(f"[Client] AES Key {aes_key.decode()}를 사용하여 암복호화 합니다.")
    #MESSAGE = client_socket.recv(BUFFER_SIZE)
    iv = client_socket.recv(16)
    #print(f"[Client] 서버로부터 AES IV 값 {iv}를 전송 받았습니다.")

    # 키 공유 스레드 및 HybridCrypto 기반 채팅 과정에서 : Client (Alice) --> ./Alice/ 폴더를 생성해야 함
    # 키 공유를 위해서
    # "/Client 폴더가 있어야 함"
    print("/Client 폴더 확인!!!")
    keySharing_thread = threading.Thread(target=keySharing_client)  ## 공개키 정보 공유 과정 수행
    keySharing_thread.start()  ## 추가
    keySharing_thread.join()  ## 추가
    print("RSA public Key 공유가 완료되었습니다. 이제 하이브리드 암호 기반 채팅이 가능합니다!!!")
    time.sleep(2)  # 키공유 스레드 종료

    # 채팅 스레드 시작
    # 수신 및 전송 스레드 실행
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    send_thread = threading.Thread(target=send_messages, args=(client_socket,))

    receive_thread.start();     send_thread.start()
    receive_thread.join();     send_thread.join()

    client_socket.close()
