import binascii

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto import Random


BLOCK_SIZE = 16 # 128bit
SALT_SIZE = 16 # 128bit
KEY_SIZE = 32 # 256bit

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

def storeUSB(salt:bytes, encryptedCEK:bytes, iv:bytes, ciphertext:bytes):
    ### 파일생성
    ### filename 입력 받아서... 파일로 저장...
    filename = input("USB Stored Filename(ex: xxx.enc):")
    f = open(filename, "wt")
    hpt = binascii.hexlify(salt) + '$****$'.encode('utf8') \
          + binascii.hexlify(encryptedCEK) + '$****$'.encode('utf8') \
          + binascii.hexlify(iv) + '$****$'.encode('utf8') \
          + binascii.hexlify(ciphertext)
    f.write(hpt.decode())
    f.close()

def readUSB():
    filename = input("USB Stored Filename(ex: xxx.enc):")
    f=open(filename, "rt")
    f.seek(0)
    salt, encryptedCEK, iv, ciphertext = f.readline().split("$****$")
    salt = bytearray.fromhex(salt)
    iv = bytearray.fromhex(iv)
    ciphertext = bytearray.fromhex(ciphertext)
    encryptedCEK = bytearray.fromhex(encryptedCEK)
    f.close()
    return salt, encryptedCEK, iv, ciphertext

def PBE_Encryption():
    # salt, iv 생성
    salt = Random.new().read(SALT_SIZE)
    iv = Random.new().read(BLOCK_SIZE)
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
    storeUSB(salt, encryptedCEK, iv, ciphertext)


def PBE_Decryption():
    salt, encryptedCEK, iv, ciphertext = readUSB()
    # password 입력
    alicePassword = inputPassword()
    # salt, password를 이용해서 gen keyKEK
    keyKEK = genKEK(salt, alicePassword)
    # decCEK
    keyCEK = decCEK(encryptedCEK, keyKEK, iv)
    # ciphertext복호화
    plaintext = aesDecrypt(ciphertext, keyCEK, iv)
    print("plaintext:", plaintext.decode())
    return plaintext

def main():
    PBE_Encryption()

    PBE_Decryption()


if __name__ == "__main__":
    main()