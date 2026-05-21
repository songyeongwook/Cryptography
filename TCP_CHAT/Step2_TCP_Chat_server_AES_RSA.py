import base64
import binascii
import socket
import threading
import time

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15, PKCS1_v1_5

HOST = "127.0.0.1"
PORT = 54321
BUFFER_SIZE = 4096
MESSAGE = "hello world"

SERVER_PRIVATE_KEY =  "./Server/server_private_key.pem"
SERVER_PUBLIC_KEY = "./Server/server_public_key.pem"
CLIENT_PUBLIC_KEY = "./Server/client_public_key.pem"

# -------------------- Base64 & File I/O --------------------
def B64Encoding(data: bytes) -> bytes:
    return base64.b64encode(data)

def B64Decoding(b64data: bytes) -> bytes:
    return base64.b64decode(b64data)

def decrypt_message(encrypted_message):
    cipher_aes = AES.new(aes_key, AES.MODE_OFB, iv=iv)
    return cipher_aes.decrypt(encrypted_message).decode()

#

def dec_ciphertext_sessionkey_bob(sessionkey_enc, ciphertext):
    with open(SERVER_PRIVATE_KEY, 'rb') as f:
        server_private_key = RSA.importKey(f.read())
    f.close()
    rsa_obj = PKCS1_OAEP.new(server_private_key)
    sessionkey_dec = rsa_obj.decrypt(sessionkey_enc)
    iv = ciphertext[:16]
    aes_obj = AES.new(sessionkey_dec, AES.MODE_CFB, iv)
    plaintext_with_sign_dec = aes_obj.decrypt(ciphertext[16:])
    return plaintext_with_sign_dec

def seperate_and_verify_sign_bob(plaintext_with_sign_dec):
    signature = plaintext_with_sign_dec[:256]
    plaintext = plaintext_with_sign_dec[256:]
    client_public_key = RSA.importKey(open(CLIENT_PUBLIC_KEY, 'rb').read())
    hash_obj = SHA512.new(plaintext)

    try:
        pkcs1_15.new(client_public_key).verify(hash_obj, signature)
        print("HybridCrypto & Signature Verification Result : True")
        return plaintext.decode()   ## 추가
    except (ValueError, TypeError):
        print("Signature Verification Result : False")
        return "Error on Verification!!!"


def receive_messages(connection):
    print("[Server] Receice_message Thread 실행!!!")
    while True:
        try:
            encrypted_message = connection.recv(BUFFER_SIZE)
            if encrypted_message:
                # 기존 코드를 주석처리하고..
                #decrypted_message = decrypt_message(encrypted_message)
                # 아래와 같이 수정
                sessionkey_enc_hex, ciphertext_hex = encrypted_message.split(b'***===***')
                sessionkey_enc = binascii.unhexlify(sessionkey_enc_hex)
                ciphertext = binascii.unhexlify(ciphertext_hex)
                # 세션키와 암호문을 이용한 복호화
                plaintext_with_sign_dec = dec_ciphertext_sessionkey_bob(sessionkey_enc, ciphertext)
                # 전자서명 분리 및 검증
                decrypted_message = seperate_and_verify_sign_bob(plaintext_with_sign_dec)  ##     변경


                print(f"\n[클라이언트 {client_address}] {B64Encoding(encrypted_message)}", flush=True)
                print(f"[클라이언트 {client_address}] {decrypted_message}", flush=True)
                print("서버:", end="", flush=True)
                if decrypted_message.lower() == 'exit':
                    break
        except:
            print("클라이언트 연결이 종료되었습니다.")
            break


def gen_server_signature(plaintext):  ## 함수 이름 변경 gen_signature --> gen_alice_signature
    server_privatekey = RSA.importKey(open(SERVER_PRIVATE_KEY, 'rb').read())
    plaintext_hash = SHA512.new(plaintext)
    signature_obj = PKCS1_v1_5.new(server_privatekey)
    signature = signature_obj.sign(plaintext_hash)
    return signature + plaintext


def gen_server_AES_ciphertext(sign_plaintext):  ## 함수 이름 변경 gen_AES_ciphertext --> gen_alice_AES_ciphertext
    sessionkey = Random.new().read(32)  # 32 bytes -> 256 bit
    client_publickey = RSA.importKey(open(CLIENT_PUBLIC_KEY, 'rb').read())
    rsa_obj = PKCS1_OAEP.new(client_publickey)
    sessionkey_enc = rsa_obj.encrypt(sessionkey)
    iv = Random.new().read(16)  # 16 bytes -> 128 bit
    aes_obj = AES.new(sessionkey, AES.MODE_CFB, iv)  # CFB 모드로 암호화
    ciphertext = iv + aes_obj.encrypt(sign_plaintext)
    return (sessionkey_enc, ciphertext)


def gen_server_output(sessionkey_enc, ciphertext):  ## 함수 이름 변경 gen_output --> gen_Alice_output
    output = (binascii.hexlify(sessionkey_enc)
              + "***===***".encode('utf-8')
              + binascii.hexlify(ciphertext))
    return output


def send_messages(connection):
    print("[Server] Send_message Thread 실행!!!")
    while True:
        message = input("서버: ")
        # 아래 코드를 대신해서 수정...
        #cipher_aes = AES.new(aes_key, AES.MODE_OFB, iv=iv)
        #encrypted_message = cipher_aes.encrypt(message.encode())
        sign_plaintext = gen_server_signature(message.encode())
        # 세션키 생성 후 AES 암호화 -> Bob의 공개키로 세션키 암호화
        sessionkey_enc, ciphertext = gen_server_AES_ciphertext(sign_plaintext )
        # Bob에게 전송할 메시지 생성 및 전송
        encrypted_message = gen_server_output(sessionkey_enc, ciphertext)

        connection.send(encrypted_message)
        if message.lower() == 'exit':
            break


def gen_server_key():
    key = RSA.generate(bits=2048)
    server_private_key = key.export_key(format='PEM')
    server_public_key =  key.publickey().export_key(format='PEM')
    with open(SERVER_PRIVATE_KEY, 'wb') as f:
        f.write(bytes(server_private_key))
    with open(SERVER_PUBLIC_KEY, 'wb') as f:
        f.write(bytes(server_public_key))
    return (server_private_key, server_public_key)

# 공개키 공유 스레드
def keySharing_server():
    # Bob의 키 생성
    server_private_key, server_public_key = gen_server_key()
    # Bob의 공개키 전송 및 Alice의 공개키 수신
    print('Server의 공개키를 Client로 전송합니다.')
    connection.send(server_public_key)     ## conn --> client_socket
    print("Waiting for Client's public key...")
    client_public_key = connection.recv(2048)  ## conn --> client_socket
    if not client_public_key:
        print('Client의 공개키를 받지 못했습니다.')
        return
    # Alice의 공개키 저장
    print(f"Received public key from Client : {client_address[0], client_address[1]}")  ## addr --> client_addr
    with open(CLIENT_PUBLIC_KEY, 'wb') as f:
        f.write(client_public_key)


if __name__ == '__main__':
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print("[Server] 서버가 클라이언트를 기다리는 중입니다...")

    connection, client_address = server_socket.accept()
    print(f"[Server] {client_address} 클라이언트가 연결되었습니다.")

    # AES 키를 공유하는 부분을 RSA 기반 키 전송 구조로 변경

    # 만일 메시지에 대해서 AES로 암복호화를 해야 한다면... ???
    # 단, AES 암호화 키를 미리 공유해야 한다는 문제점이 발생함
    aes_key = b"0123456789012345"
    print(f"[Server] AES Key {aes_key.decode()}를 사용하여 암복호화 합니다.")
    iv = get_random_bytes(16)  # OFB 모드용 초기화 벡터 생성
    connection.send(iv)
    #client_socket.send(MESSAGE.encode())
    print(f"[Server] 클라이언트로 AES IV {iv}를 전송하였습니다.")

    # 키 공유 스레드 실행 및 HybridCrypto 기반 채팅 과정에서 : Server (Bob) --> ./Bob/ 폴더를 생성해야 함
    # 키 공유를 위해서
    # "/Server 폴더가 있어야 함"
    print("/Server 폴더 확인!!!")
    keySharing_thread = threading.Thread(target=keySharing_server)  ## 공개키 정보 공유 과정 수행
    keySharing_thread.start()  ## 추가
    keySharing_thread.join()  ## 추가
    print("RSA public Key 공유가 완료되었습니다. 이제 하이브리드 암호 기반 채팅이 가능합니다!!!")
    time.sleep(2)  # 키공유 스레드 종료
    # 채팅 스레드 실행

    # 수신 및 전송 스레드 실행
    receive_thread = threading.Thread(target=receive_messages, args=(connection,))
    send_thread = threading.Thread(target=send_messages, args=(connection,))

    receive_thread.start();     send_thread.start()
    receive_thread.join();     send_thread.join()

    connection.close();     server_socket.close()