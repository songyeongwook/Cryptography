#입력
import binascii

from Crypto.Cipher import AES
from Crypto.Hash import SHA512, HMAC
from Crypto import Random
import time
import struct


BLOCK_SIZE = 16 # 128bit
SALT_SIZE = 16 # 128bit
KEY_SIZE = 32 # 256bit

# 시간 동기화 기반 IV 생성 함수 (1분 단위)
def get_time_synced_iv():
    ts = int(time.time() // 60)
    ts_bytes = struct.pack('>Q', ts)  # 8바이트 big-endian
    rand_bytes = Random.new().read(BLOCK_SIZE - len(ts_bytes))
    iv = ts_bytes + rand_bytes
    return iv

# 현재 시간 구간의 IV만 반환
def get_current_iv():
    ts = int(time.time() // 120)
    ts_bytes = struct.pack('>Q', ts)
    pad = b'\x00' * (BLOCK_SIZE - len(ts_bytes))
    iv = ts_bytes + pad
    return iv

def inputPassword() -> bytes:
    password = input("Input Password for PBE:").encode()
    print("Alice's password: %s"% password.decode())
    return password

def inputMessage() -> bytes:
    message = input("Input Message:").encode()
    print("Alice's message: %s" % message)
    return message

def aesEncrypt(message:bytes, key:bytes, iv:bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_OFB, iv)
    return cipher.encrypt(message)

def aesDecrypt(encrypted, key, iv):
    ciphertext = AES.new(key, AES.MODE_OFB, iv)
    return ciphertext.decrypt(encrypted)

def genKEK(salt:bytes, password:bytes):
    inputValue = salt + password
    hashFunc = SHA512.new()
    hashFunc.update(inputValue)
    keyKEK = hashFunc.digest()
    print("key KEK: ", keyKEK.hex())
    return keyKEK # SHA512 = 512bit *나중에 512중 일부만 사용, AES 키로 사용됨 (128 또는 256비트만 사용)


def genCEK():
    keyCEK = Random.new().read(KEY_SIZE)
    ###
    return keyCEK

def encCEK(keyCEK, keyKEK, iv):
    encryptedCEK = aesEncrypt(keyCEK, keyKEK[:32], iv)
    return encryptedCEK

def decCEK(encryptedCEK, keyKEK, iv):
    keyCEK = aesDecrypt(encryptedCEK, keyKEK[:32], iv)
    return keyCEK

def storeUSB(salt:bytes, encryptedCEK:bytes, iv:bytes, ciphertext:bytes, password:bytes):
    ### 파일생성
    ### filename 입력 받아서... 파일로 저장...
    filename = input("USB Stored Filename(ex: xxx.enc):")
    # 비밀번호 검증을 위한 해시 생성
    passwordHash = SHA512.new(password).digest()
    
    f = open(filename, "wt")
    hpt = binascii.hexlify(salt) + '$****$'.encode('utf8') \
          + binascii.hexlify(encryptedCEK) + '$****$'.encode('utf8') \
          + binascii.hexlify(iv) + '$****$'.encode('utf8') \
          + binascii.hexlify(ciphertext) + '$****$'.encode('utf8') \
          + binascii.hexlify(passwordHash) #비번 해시 추가
    f.write(hpt.decode())
    f.close()

def readUSB():
    filename = input("USB Stored Filename(ex: xxx.enc):")
    f=open(filename, "rt")
    f.seek(0)
    data = f.readline().split("$****$")
    salt = bytearray.fromhex(data[0])
    encryptedCEK = bytearray.fromhex(data[1])
    iv = bytearray.fromhex(data[2])
    ciphertext = bytearray.fromhex(data[3])
    # 패스워드 읽어 들이기
    passwordHash = bytearray.fromhex(data[4])
    f.close()
    return salt, encryptedCEK, iv, ciphertext, passwordHash

def PBE_Encryption():
    # salt, iv 생성
    salt = Random.new().read(SALT_SIZE)
    iv = get_time_synced_iv()
    print("salt:", salt)
    print("iv:", iv)
    # input Password
    alicePassword = inputPassword()
    # input Message
    Message = inputMessage()
    # gen keyKEK
    keyKEK = genKEK(salt, alicePassword)
    # gen keyCEK
    keyCEK = genCEK()
    # using keyCEK --> message AES 암호화
    ciphertext = aesEncrypt(Message, keyCEK, iv)
    # encCEK using keyKEK
    encryptedCEK = encCEK(keyCEK, keyKEK, iv)
    # store USB
    storeUSB(salt, encryptedCEK, iv, ciphertext, alicePassword)


# ---- 패스워드 검증 함수 추가 ---------
def verifyPassword(password:bytes, storedPasswordHash:bytes) -> bool:  
    hashFunc = SHA512.new()
    hashFunc.update(password)
    computedHash = hashFunc.digest()
    return computedHash == storedPasswordHash


def PBE_Decryption():
    salt, encryptedCEK, iv, ciphertext, storedPasswordHash = readUSB()
    attempt_count = 0
    start_time = int(time.time())
    while True:
        # 1분 초과 시 즉시 종료 (입력창 없이)
        if int(time.time()) - start_time > 50:
            print(f"입력 시간 초과: 1분 내에 복호화 시도 {attempt_count}회 했으나 실패하여 종료합니다.")
            break
        attempt_count += 1
        alicePassword = inputPassword()
        keyKEK = genKEK(salt, alicePassword)
        if not verifyPassword(alicePassword, storedPasswordHash):
            print(f" 비밀번호가 틀렸습니다. (시도 {attempt_count})")
            continue
        # 현재 시간 구간의 IV만 사용
        try_iv = get_current_iv()
        try:
            keyCEK = decCEK(encryptedCEK, keyKEK, try_iv)
            plaintext = aesDecrypt(ciphertext, keyCEK, try_iv)
            print(f"\n 복호화 성공했습니다 (총 {attempt_count}회 시도)")
            print("plaintext:", plaintext.decode())
            return plaintext
        except Exception:
            print(f"IV 동기화 실패: 시간 구간이 맞지 않습니다. (시도 {attempt_count})")

def main():
    print("---------암호화---------")
    PBE_Encryption()
    print("---------복호화---------")
    PBE_Decryption()


if __name__ == "__main__":
    main()
       