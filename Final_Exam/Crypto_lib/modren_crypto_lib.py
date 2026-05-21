from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

# ---- RSA 디지털 서명 ----

def rsa_sign(message: bytes, private_key_pem: str) -> bytes:
    key = RSA.import_key(private_key_pem)
    h = SHA512.new(message)
    signature = pkcs1_15.new(key).sign(h)
    return signature


def rsa_verify(message: bytes, signature: bytes, public_key_pem: str) -> bool:
    key = RSA.import_key(public_key_pem)
    h = SHA512.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# ---- AES-CBC ----

def encrypt_aes_cbc(message: str, key: bytes) -> tuple[str, str]:
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct


def decrypt_aes_cbc(iv: str, ciphertext: str, key: bytes) -> str:
    try:
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ciphertext)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()
    except Exception as e:
        return f"복호화 오류: {str(e)}"


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return public_key, private_key


def encrypt_rsa(message, public_key):
    try:
        key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(key)
        encrypted = cipher.encrypt(message.encode())
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        return f"암호화 오류: {str(e)}"


def decrypt_rsa(ciphertext, private_key):
    try:
        key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(key)
        decrypted = cipher.decrypt(base64.b64decode(ciphertext))
        return decrypted.decode()
    except Exception as e:
        return f"복호화 오류: {str(e)}"


def calculate_sha512(message):
    return hashlib.sha512(message.encode()).hexdigest()


# ---- AES-OFB 유틸 ----

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def aes_ofb_encrypt(plaintext: str, key: bytes):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    ciphertext = cipher.encrypt(plaintext.encode("utf-8"))
    return b64e(iv), b64e(ciphertext)


def aes_ofb_decrypt(iv_b64: str, ciphertext_b64: str, key: bytes) -> str:
    iv = b64d(iv_b64)
    ciphertext = b64d(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode("utf-8")


# ---- AES-GCM (인증된 암호화) ----

def encrypt_aes_gcm(plaintext: str, key: bytes):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(nonce).decode(), base64.b64encode(ct).decode(), base64.b64encode(tag).decode()


def decrypt_aes_gcm(nonce_b64: str, ct_b64: str, tag_b64: str, key: bytes):
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    tag = base64.b64decode(tag_b64)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt.decode()
    except Exception as e:
        return f"복호화/검증 오류: {e}"
