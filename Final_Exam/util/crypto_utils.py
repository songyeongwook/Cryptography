# crypto_utils.py
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, SHA256
from Crypto.Util.number import getPrime
import socket
import threading

# --- PBE (Password-Based Encryption) ---
# PBKDF2를 사용하여 패스워드에서 키를 유도하고, 이 키로 프라이빗 키를 암호화/복호화합니다.

def get_pbe_key(password, salt):
    """패스워드와 솔트로부터 32바이트 AES 키를 유도 (PBKDF2-SHA512)"""
    # 요구사항의 SHA512 적용
    return PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA512)

def encrypt_private_key(private_key_pem, password):
    """PBE를 사용해 RSA 개인키를 암호화합니다 (AES-GCM)."""
    salt = get_random_bytes(16)
    key = get_pbe_key(password, salt)
    cipher_aes = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(private_key_pem)
    
    # JSON으로 암호화된 데이터, 솔트, 논스, 태그를 모두 저장
    return json.dumps({
        'salt': salt.hex(),
        'nonce': cipher_aes.nonce.hex(),
        'tag': tag.hex(),
        'ciphertext': ciphertext.hex()
    })

def decrypt_private_key(encrypted_key_json, password):
    """PBE로 암호화된 RSA 개인키를 복호화합니다."""
    try:
        data = json.loads(encrypted_key_json)
        salt = bytes.fromhex(data['salt'])
        nonce = bytes.fromhex(data['nonce'])
        tag = bytes.fromhex(data['tag'])
        ciphertext = bytes.fromhex(data['ciphertext'])
        
        key = get_pbe_key(password, salt)
        cipher_aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_pem = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return decrypted_pem
    except (ValueError, KeyError, TypeError):
        return None # 패스워드 불일치 또는 데이터 손상

# --- RSA ---

def generate_rsa_keys():
    """RSA-2048 키 쌍을 생성합니다."""
    key = RSA.generate(2048)
    private_key_pem = key.export_key('PEM')
    public_key_pem = key.publickey().export_key('PEM')
    return private_key_pem, public_key_pem

def rsa_encrypt(data, public_key_pem):
    """RSA 공개키로 데이터를 암호화합니다 (세션 키 암호화용)."""
    recipient_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data

def rsa_decrypt(encrypted_data, private_key_pem):
    """RSA 개인키로 데이터를 복호화합니다 (세션 키 복호화용)."""
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    return decrypted_data

# --- AES ---

def aes_encrypt(message, key):
    """AES-256 (GCM)으로 메시지를 암호화합니다."""
    cipher_aes = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
    # nonce, tag, ciphertext를 함께 반환해야 함
    return ciphertext, tag, cipher_aes.nonce

def aes_decrypt(ciphertext, tag, nonce, key):
    """AES-256 (GCM)으로 메시지를 복호화합니다."""
    try:
        cipher_aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return decrypted_message.decode('utf-8')
    except (ValueError, KeyError):
        return "[복호화 실패: 키가 일치하지 않거나 메시지가 변조되었습니다]"

# --- HASH (SHA-256) ---

def get_message_hash(message):
    """요구사항의 SHA-256 무결성 해시를 생성합니다."""
    if isinstance(message, str):
        message = message.encode('utf-8')
    h = SHA256.new(message)
    return h.hexdigest()


# --- Diffie-Hellman (modular) ---
def generate_dh_params(bits: int = 2048):
    """DH 파라미터(p, g) 생성 (테스트/시연용). p는 소수, g는 생성자."""
    p = getPrime(bits)
    g = 2
    return p, g


def generate_dh_keypair(p: int, g: int):
    """DH 개인키(priv)와 공개키(pub)를 생성합니다."""
    priv = int.from_bytes(get_random_bytes(256), 'big')
    pub = pow(g, priv, p)
    return priv, pub


def derive_dh_shared(priv: int, peer_pub: int, p: int) -> bytes:
    """상대 공개키와 자신의 개인키로 공유 비밀을 계산하고 SHA-256으로 KDF 수행해 32바이트 키 반환."""
    shared = pow(peer_pub, priv, p)
    return SHA256.new(str(shared).encode('utf-8')).digest()