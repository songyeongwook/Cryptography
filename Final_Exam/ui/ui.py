# --- AI ----- 
import os
import sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import streamlit as st
import base64
import hashlib
import time
import socket
import threading
import json
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from Crypto_lib.modren_crypto_lib import (
    encrypt_aes_cbc, decrypt_aes_cbc, aes_ofb_encrypt, aes_ofb_decrypt,
    encrypt_aes_gcm, decrypt_aes_gcm, generate_rsa_keys, rsa_sign, rsa_verify
)

from Crypto_lib.classic_crypto import (
    caesar_encrypt, caesar_decrypt, chi_square_score, affine_encrypt, affine_decrypt,
    vigenere_encrypt, vigenere_decrypt, combined_encrypt, combined_decrypt, gcd, mod_inverse
)

import util.crypto_utils as crypto
import util.blockchain_utils as bc

st.set_page_config(
    page_title="메시지 보안 도구",
    page_icon="🔐",
    layout="wide"
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;700&display=swap');
    .stApp { background-color: #1e1e1e; font-family: 'Noto Sans KR', sans-serif; color: #e0e0e0; }
    h1 { color: #00bcd4; text-align: center; font-weight: 700; padding-bottom: 20px; border-bottom: 2px solid #333; }
    h2 { color: #00bcd4; border-left: 5px solid #00bcd4; padding-left: 15px; margin-top: 20px; }
    .stTabs [data-baseweb="tab-list"] { gap: 24px; background-color: #252526; padding: 10px; border-radius: 8px; }
    .stTabs [data-baseweb="tab"] { height: 50px; background-color: #333; border-radius: 8px; color: #a0a0a0; font-weight: 500; }
    .stTabs [data-baseweb="tab"][aria-selected="true"] { background-color: #00838f; color: white; font-weight: 700; }
    .stButton>button { border: none; border-radius: 8px; padding: 10px 20px; color: white; background-color: #0097a7; }
    .stCodeBlock, pre { border: 1px solid #444; border-radius: 8px; background-color: #2a2a2a; padding: 15px !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🔐 메시지 보안 도구 (모듈화된 버전)")

def add_log(log_message):
    if 'logs' not in st.session_state:
        st.session_state['logs'] = []
    st.session_state['logs'].append(f"[{time.strftime('%H:%M:%S')}] {log_message}")


def start_tcp_server(host: str, port: int, blockchain, logs_append):
    def handle_client(conn, addr):
        try:
            with conn:
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                try:
                    msg = json.loads(data.decode('utf-8'))
                except Exception:
                    logs_append(f"[TCP] 잘못된 JSON 수신 from {addr}")
                    return
                blockchain.add_transaction(msg)
                new_block = blockchain.mine_pending_transactions()
                if new_block:
                    logs_append(f"[TCP] 블록 채굴 완료(Index {new_block.index})")
        except Exception as e:
            logs_append(f"[TCP] 클라이언트 처리 오류: {e}")

    def server_loop():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((host, port))
            srv.listen(5)
            logs_append(f"[TCP] 서버 시작: {host}:{port}")
            while True:
                conn, addr = srv.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            logs_append(f"[TCP] 서버 오류: {e}")
        finally:
            try:
                srv.close()
            except Exception:
                pass

    t = threading.Thread(target=server_loop, daemon=True)
    t.start()
    return t


def send_via_tcp(bundle: dict, host: str = '127.0.0.1', port: int = 9632) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.sendall(json.dumps(bundle).encode('utf-8'))
        s.shutdown(socket.SHUT_WR)
        s.close()
        return True
    except Exception:
        return False



tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["AES-CBC", "SHA-512+AES", "RSA", "고전 암호", "AES-OFB", "RSA 디지털 서명", "Mini Telegram"])

with tab1:
    st.header("AES-CBC 대칭키 암호화")
    key_size = st.radio(
        "AES 키 크기 선택",
        ["128비트 (16바이트)", "192비트 (24바이트)", "256비트 (32바이트)"],
        horizontal=True
    )
    key_bytes = {"128비트 (16바이트)":16, "192비트 (24바이트)":24, "256비트 (32바이트)":32}[key_size]

    if 'cbc_aes_key' not in st.session_state or len(st.session_state.get('cbc_aes_key', b'')) != key_bytes:
        st.session_state['cbc_aes_key'] = get_random_bytes(key_bytes)

    colk1, colk2 = st.columns([3,1])
    with colk1:
        st.code(base64.b64encode(st.session_state['cbc_aes_key']).decode(), language='text')
    with colk2:
        if st.button("🔄 새 랜덤 키 생성", key="new_cbc_key"):
            st.session_state['cbc_aes_key'] = get_random_bytes(key_bytes)
            st.success(f"새로운 {key_size} AES 키가 생성되었습니다.")

    aes_message = st.text_area("암호화할 메시지 입력", key="aes_message")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔒 AES 암호화", key="encrypt_aes"):
            if aes_message:
                key = st.session_state['cbc_aes_key']
                iv, encrypted = encrypt_aes_cbc(aes_message, key)
                st.session_state['aes_iv'] = iv
                st.session_state['aes_encrypted'] = encrypted
                st.code(f"IV: {iv}\nCiphertext: {encrypted}", language='text')
            else:
                st.error("메시지를 입력하세요.")
    with col2:
        if st.button("🔓 AES 복호화", key="decrypt_aes"):
            if 'aes_iv' in st.session_state and 'aes_encrypted' in st.session_state:
                key = st.session_state['cbc_aes_key']
                decrypted = decrypt_aes_cbc(st.session_state['aes_iv'], st.session_state['aes_encrypted'], key)
                st.text_area("복호화된 메시지", decrypted, height=150)
            else:
                st.error("먼저 메시지를 암호화하세요.")

with tab2:
    st.header("SHA-512 기반 무결성 포함 AES 암복호화")
    with st.expander("ℹ️ E(H(M) || M) 방식이란?"):
        st.markdown("""
        이 방식은 메시지의 **기밀성**과 **무결성**을 동시에 제공하는 간단한 방법입니다.
        - **암호화**: 메시지(M)의 해시(H(M))를 계산한 뒤, 해시와 메시지를 합쳐(`H(M) || M`) AES로 암호화합니다.
        - **복호화 및 검증**: 암호문을 복호화하여 해시와 메시지를 분리합니다. 분리된 메시지로 다시 해시를 계산하여, 복호화된 해시와 일치하는지 비교합니다.
        
        만약 두 해시 값이 일치하면 메시지가 전송 중에 변조되지 않았음을 확신할 수 있습니다.
        """)

    # 세션에 키 보관
    if 'sha_aes_key' not in st.session_state:
        st.session_state['sha_aes_key'] = get_random_bytes(32) # AES-256

    st.subheader("🔑 키 관리 (AES-256)")
    colk1, colk2 = st.columns([3, 1])
    with colk1:
        st.code(base64.b64encode(st.session_state['sha_aes_key']).decode(), language='text')
    with colk2:
        if st.button("🔄 새 랜덤 키 생성"):
            st.session_state['sha_aes_key'] = get_random_bytes(32)
            st.success("새 AES-256 키가 생성되었습니다.")

    sha_plain = st.text_area("암호화할 메시지 입력", key="sha_plain", placeholder="무결성을 검증할 메시지를 입력하세요.")
    col1, col2 = st.columns(2)

    with col1:
        if st.button("🔒 E(H(M)||M) 암호화", key="sha_integrity_enc"):
            if sha_plain:
                key = st.session_state['sha_aes_key']
                digest = hashlib.sha512(sha_plain.encode()).digest()
                payload = digest + sha_plain.encode()
                cipher = AES.new(key, AES.MODE_CBC)
                ct = cipher.encrypt(pad(payload, AES.block_size))
                iv = base64.b64encode(cipher.iv).decode()
                ct_b64 = base64.b64encode(ct).decode()

                st.session_state['sha_int_iv'] = iv
                st.session_state['sha_int_ct'] = ct_b64

                st.markdown("---")
                st.subheader("📝 암호화 및 무결성 보장 과정")
                st.markdown("**1. 메시지 해시 계산 (SHA-512)**")
                st.code(f"H(M) = SHA512('{sha_plain[:20]}...')\n=> {digest.hex()}", language='text')

                st.markdown("**2. 페이로드 결합: `H(M) || M`**")
                st.markdown("계산된 64바이트 해시값을 원본 메시지 앞에 붙입니다.")
                st.code(f"Payload = (64 bytes hash) + ({len(sha_plain.encode())} bytes message)", language='text')

                st.markdown("**3. AES-CBC 암호화**")
                st.markdown("결합된 페이로드를 `AES-256-CBC` 방식으로 암호화합니다.")
                st.code(f"IV: {iv}\nCiphertext: {ct_b64}", language='text')
                st.success("암호화 완료")
                st.markdown("**IV:**")
                st.code(iv, language='text')
                st.markdown("**Ciphertext:**")
                st.code(ct_b64, language='text')
            else:
                st.error("메시지를 입력하세요.")

    with col2:
        if st.button("🔓 복호화 및 검증", key="sha_integrity_dec"):
            if 'sha_int_iv' in st.session_state and 'sha_int_ct' in st.session_state:
                try:
                    key = st.session_state['sha_aes_key']
                    iv = base64.b64decode(st.session_state['sha_int_iv'])
                    ct = base64.b64decode(st.session_state['sha_int_ct'])
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    digest_rec = pt[:hashlib.sha512().digest_size]
                    msg_rec = pt[hashlib.sha512().digest_size:]
                    
                    digest_calc = hashlib.sha512(msg_rec).digest()
                    
                    st.markdown("---")
                    st.subheader("🔄 복호화 및 무결성 검증 과정")
                    st.markdown("**1. AES-CBC 복호화**")
                    st.markdown("수신된 암호문을 키와 IV로 복호화하여 `H(M) || M` 페이로드를 복원합니다.")
                    st.markdown("**2. 다이제스트 및 메시지 분리**")
                    st.markdown("복호화된 페이로드에서 앞 64바이트(복원된 다이제스트)와 나머지(복원된 메시지)를 분리합니다.")
                    st.markdown("**3. 다이제스트 재계산 및 비교**")
                    st.markdown("복원된 메시지로 SHA-512 해시를 다시 계산하고, 1번 과정에서 복원된 다이제스트와 비교합니다.")

                    st.subheader("� 검증 결과")
                    st.text_area("복호화된 메시지", msg_rec.decode(), height=100)
                    st.markdown("**복호화된 다이제스트:**")
                    st.code(digest_rec.hex(), language='text')
                    st.markdown("**계산된 다이제스트:**")
                    st.code(digest_calc.hex(), language='text')

                    if digest_rec == digest_calc:
                        st.success("✅ 무결성 검증 성공: 메시지가 변조되지 않았습니다.")
                    else:
                        st.error("❌ 무결성 검증 실패: 메시지가 변경되었거나 잘못된 키입니다.")
                except Exception as e:
                    st.error(f"복호화 오류: {e}")
            else:
                st.error("먼저 암호문을 생성하세요.")

with tab3:
    st.header("Alice → Bob 시뮬레이션")
    with st.expander("ℹ️ 시뮬레이션 설명"):
        st.markdown("""
        Alice가 선택한 암호화 알고리즘으로 메시지를 암호화하여 네트워크(중간자)로 전송하고,
        Bob이 수신하여 복호화하는 과정을 시뮬레이션합니다. 중간에서 공격자(Injection)가 암호문을 변조해
        Bob의 복호화 결과가 어떻게 되는지 확인할 수 있습니다.
        """)

    # 키 및 알고리즘 설정
    st.subheader("🔑 키 및 알고리즘 설정")
    colk1, colk2 = st.columns(2)
    with colk1:
        st.markdown("**RSA 키 쌍 (Alice & Bob)**")
        if 'alice_public' not in st.session_state or 'bob_public' not in st.session_state:
            if st.button("🔄 ALICE/BOB RSA 키 생성"):
                alice_public, alice_private = generate_rsa_keys()
                bob_public, bob_private = generate_rsa_keys()
                st.session_state['alice_public'] = alice_public
                st.session_state['alice_private'] = alice_private
                st.session_state['bob_public'] = bob_public
                st.session_state['bob_private'] = bob_private
                st.success("Alice와 Bob의 RSA 키 쌍이 생성되었습니다.")
        if 'bob_public' in st.session_state:
            st.text_area("BOB 공개키 (암호화용)", st.session_state['bob_public'], height=100)

    with colk2:
        st.markdown("**공유 대칭키 (AES용)**")
        if 'shared_aes_key' not in st.session_state:
            st.session_state['shared_aes_key'] = get_random_bytes(16)
        if st.button("🔄 새 대칭키 생성"):
            st.session_state['shared_aes_key'] = get_random_bytes(16)
        st.code(base64.b64encode(st.session_state['shared_aes_key']).decode(), language='text')
        
    algo = st.selectbox("암호화 알고리즘 선택", ["AES-CBC", "AES-OFB", "SHA512+AES(E(H||M))"], index=0)

    st.subheader("Alice: 암호화 및 전송")
    alice_input = st.text_area("Alice가 보낼 메시지", key='alice_input', placeholder="Alice의 비밀 메시지...")
    
    if st.button("🚀 Alice 암호화 & 전송"):
        if not alice_input:
            st.error("메시지를 입력하세요.")
        else:
            packet = {"alg": algo}
            # ... (기존 암호화 로직은 동일)
            if algo == "AES-CBC":
                key = st.session_state['shared_aes_key']
                cipher = AES.new(key, AES.MODE_CBC)
                ct = cipher.encrypt(pad(alice_input.encode(), AES.block_size))
                packet['iv'] = base64.b64encode(cipher.iv).decode()
                packet['ct'] = base64.b64encode(ct).decode()
                packet['explain'] = f"AES-CBC: IV={packet['iv'][:10]}..., 블록 사이즈=16, 패딩 PKCS7"
            elif algo == "AES-OFB":
                key = st.session_state['shared_aes_key']
                iv_b64, ct_b64 = aes_ofb_encrypt(alice_input, key)
                packet['iv'] = iv_b64
                packet['ct'] = ct_b64
                packet['explain'] = "AES-OFB: 스트림 방식, IV와 키로 키스트림 생성 후 XOR"
            elif algo == "SHA512+AES(E(H||M))":
                key = hashlib.sha512(st.session_state['shared_aes_key']).digest()[:32]
                digest = hashlib.sha512(alice_input.encode()).digest()
                payload = digest + alice_input.encode()
                cipher = AES.new(key, AES.MODE_CBC)
                ct = cipher.encrypt(pad(payload, AES.block_size))
                packet['iv'] = base64.b64encode(cipher.iv).decode()
                packet['ct'] = base64.b64encode(ct).decode()
                packet['explain'] = "E(H(M)||M): 메시지 앞에 SHA-512 다이제스트를 붙여 암호화. 복호화 후 무결성 검증 가능"

            if packet:
                st.session_state['alice_packet'] = packet
                st.success("Alice가 암호문을 생성하여 전송했습니다. (중간자로 전달됨)")

    # show on-wire packet
    st.subheader("📡 네트워크(중간자) 패킷")
    if 'alice_packet' in st.session_state:
        pkt = st.session_state['alice_packet'].copy()
        st.info(f"**알고리즘:** {pkt.get('alg')} | **설명:** {pkt.get('explain')}")
        st.json(pkt)

        # Bob: 복호화
        st.subheader("Bob: 수신 및 복호화")
        if st.button("📥 Bob 복호화 시도"):
            try:
                final_pkt = st.session_state['alice_packet']
                alg = final_pkt.get('alg')
                # ... (기존 복호화 로직은 동일)
                if alg == "AES-CBC":
                    key = st.session_state['shared_aes_key']
                    iv = base64.b64decode(final_pkt['iv'])
                    ct = base64.b64decode(final_pkt['ct'])
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    st.success("복호화 성공")
                    st.code(pt.decode())
                elif alg == "AES-OFB":
                    key = st.session_state['shared_aes_key']
                    pt = aes_ofb_decrypt(final_pkt['iv'], final_pkt['ct'], key)
                    st.success("복호화 성공")
                    st.code(pt)
                elif alg == "SHA512+AES(E(H||M))":
                    key = hashlib.sha512(st.session_state['shared_aes_key']).digest()[:32]
                    iv = base64.b64decode(final_pkt['iv'])
                    ct = base64.b64decode(final_pkt['ct'])
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    pt = unpad(cipher.decrypt(ct), AES.block_size)
                    digest_rec = pt[:hashlib.sha512().digest_size]
                    msg_rec = pt[hashlib.sha512().digest_size:]
                    digest_calc = hashlib.sha512(msg_rec).digest()
                    st.code(f"복호화된 메시지: {msg_rec.decode()}\n복호화된 다이제스트: {digest_rec.hex()}\n계산한 다이제스트: {digest_calc.hex()}")
                    if digest_rec == digest_calc:
                        st.success("✅ 무결성 검증 성공")
                    else:
                        st.error("❌ 무결성 검증 실패: 메시지가 변조되었거나 잘못된 키")
            except Exception as e:
                st.error(f"복호화 중 치명적 오류 발생: {e}")

with tab4:
    st.header("고전 암호 시스템")
    
    with st.expander("ℹ️ 고전 암호 시스템 소개"):
        st.markdown("""
        1. **카이사르 암호 (Caesar Cipher)**: 각 문자를 일정한 수만큼 알파벳 상에서 이동시키는 가장 간단한 형태의 치환 암호입니다.
        2. **아핀 암호 (Affine Cipher)**: 일차 함수((x) = ax + b \pmod{m}$)를 사용한 치환 암호로, 카이사르보다 복잡한 치환을 제공합니다.
        3. **비즈네르 암호 (Vigenere Cipher)**: 여러 개의 카이사르 암호를 키워드를 이용해 반복적으로 적용하는 다중 치환 암호입니다.
        4. **조합 암호**: 카이사르 암호와 아핀 암호를 순차적으로 적용하여 다중 암호화로 보안성을 향상시킵니다.
        """)
    
    cipher_type = st.radio(
        "암호화 방식 선택",
        ["카이사르 암호", "아핀 암호", "비즈네르 암호", "조합 암호"],
        horizontal=True,
        help="사용할 고전 암호 방식을 선택하세요"
    )
    
    text = st.text_area("암호화/복호화할 텍스트 입력", key="classic_text", placeholder="영문 텍스트를 입력하세요...")
    
    if cipher_type == "카이사르 암호":
        shift = st.slider("시프트 값", min_value=1, max_value=25, value=3)
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔒 카이사르 암호화", key="caesar_enc"):
                if text:
                    encrypted = caesar_encrypt(text, shift)
                    st.session_state['caesar_result'] = encrypted
                    st.markdown("---")
                    # --- AI 활용: 수학 공식 표현 ---
                    # 암호화 원리를 명확하게 전달하기 위해, 카이사르 암호의 수학적 표현을
                    # Streamlit의 st.latex 기능을 사용하여 수식으로 표현하는 방법을 AI의 도움을 받아 구현했습니다.
                    st.subheader("🔄 암호화 과정")
                    st.markdown(f"각 알파벳 문자를 알파벳 순서상 **{shift}칸** 뒤로 이동시킵니다.")
                    example_char = next((c for c in text if c.isalpha()), 'A')
                    encrypted_char = caesar_encrypt(example_char, shift)
                    st.latex(f"E(x) = (x + {shift}) \\pmod{{26}}")
                    st.markdown(f"**예시**: `{example_char}` → `{encrypted_char}`")


                    st.text_area("암호화 결과", encrypted, height=100)
        
        with col2:
            if st.button("🔓 카이사르 복호화", key="caesar_dec"):
                if 'caesar_result' in st.session_state:
                    decrypted = caesar_decrypt(st.session_state['caesar_result'], shift)
                    st.text_area("복호화 결과", decrypted, height=100)

        st.markdown("---")
        st.subheader("💥 카이사르 암호 해독 (Brute-Force with Chi-Square)")
        if st.button("🤖 카이제곱 통계로 암호 해독", help="암호화된 텍스트에 대해 모든 키를 시도하고, 통계적으로 가장 그럴듯한 평문을 찾습니다."):
            if 'caesar_result' in st.session_state and st.session_state['caesar_result']:
                ciphertext = st.session_state['caesar_result']
                scores = []
                for k in range(26):
                    decrypted = caesar_decrypt(ciphertext, k)
                    score = chi_square_score(decrypted)
                    scores.append((score, k, decrypted))
                
                scores.sort(key=lambda x: x[0]) # 점수가 낮은 순으로 정렬
                st.markdown("**가장 가능성 높은 복호화 결과 (상위 5개):**")
                for score, key, result in scores[:5]:
                    st.info(f"**Key: {key}** (Score: {score:.2f})\n> {result}")
    
    elif cipher_type == "아핀 암호":
        col1, col2 = st.columns(2)
        with col1:
            a = st.number_input("a 값 (26과 서로소여야 함)", min_value=1, max_value=25, value=5, step=2)
        with col2:
            b = st.number_input("b 값", min_value=0, max_value=25, value=8)
        
        if gcd(a, 26) != 1:
            st.error(f"a={a}는 26과 서로소가 아닙니다. 다른 값을 선택하세요. (예: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)")
        else:
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔒 아핀 암호화", key="affine_enc"):
                    if text:
                        encrypted = affine_encrypt(text, a, b)
                        st.session_state['affine_result'] = encrypted
                        st.markdown("---")
                        st.subheader("🔢 암호화 함수")
                        st.latex(f"E(x) = ({a}x + {b}) \\pmod{{26}}")
                        example_char = next((c for c in text if c.isalpha()), 'A')
                        encrypted_char = affine_encrypt(example_char, a, b)
                        st.markdown(f"**예시**: `{example_char}` → `{encrypted_char}`")
                        st.text_area("암호화 결과", encrypted, height=100)
            
            with col2:
                if st.button("🔓 아핀 복호화", key="affine_dec"):
                    if 'affine_result' in st.session_state:
                        st.markdown("---")
                        st.subheader("🔢 복호화 함수")
                        a_inv = mod_inverse(a, 26)
                        st.latex(f"D(y) = {a_inv}(y - {b}) \\pmod{{26}}")
                        decrypted = affine_decrypt(st.session_state['affine_result'], a, b)
                        st.text_area("복호화 결과", decrypted, height=100)
    
    elif cipher_type == "비즈네르 암호":
        vigenere_key = st.text_input("비즈네르 키 (영문)", key="vigenere_classic_key", placeholder="e.g., 'KEY'")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔒 비즈네르 암호화", key="vigenere_enc"):
                if text and vigenere_key:
                    try:
                        encrypted = vigenere_encrypt(text, vigenere_key)
                        st.session_state['vigenere_result'] = encrypted
                        st.markdown("---")
                        st.subheader("🔄 암호화 과정")
                        st.markdown(f"평문 `'{text[:10]}...'`을 키 `'{vigenere_key}'`를 반복 사용하여 각 문자마다 다른 시저 암호(이동값)를 적용합니다.")
                        st.latex(f"E_i(P_i) = (P_i + K_i) \\pmod{{26}}")

                        st.text_area("암호화 결과", encrypted, height=100)
                    except ValueError as e:
                        st.error(str(e))
                else:
                    st.warning("텍스트와 키를 모두 입력하세요.")
        with col2:
            if st.button("🔓 비즈네르 복호화", key="vigenere_dec"):
                if 'vigenere_result' in st.session_state and vigenere_key:
                    decrypted = vigenere_decrypt(st.session_state['vigenere_result'], vigenere_key)
                    st.text_area("복호화 결과", decrypted, height=100)
                else:
                    st.warning("먼저 암호화하거나, 키를 입력하세요.")

    else: # 조합 암호
        st.markdown("### ⚙️ 조합 암호 매개변수")
        col1, col2, col3 = st.columns(3)
        with col1:
            caesar_shift = st.number_input("카이사르 시프트", min_value=1, max_value=25, value=3)
        with col2:
            affine_a = st.number_input("아핀 a", min_value=1, max_value=25, value=5, step=2)
        with col3:
            affine_b = st.number_input("아핀 b", min_value=0, max_value=25, value=8)
        
        if gcd(affine_a, 26) != 1:
            st.error(f"a={affine_a}는 26과 서로소가 아닙니다.")
        else:
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔒 조합 암호화", key="combined_enc"):
                    if text:
                        encrypted = combined_encrypt(text, caesar_shift, affine_a, affine_b)
                        st.session_state['combined_result'] = encrypted
                        st.markdown("---")
                        st.subheader("🔄 조합 암호화 과정")
                        st.markdown("**1단계: 카이사르 암호화**")
                        st.latex(f"C(x) = (x + {caesar_shift}) \\pmod{{26}}")
                        st.markdown("**2단계: 아핀 암호화**")
                        st.latex(f"A(y) = ({affine_a}y + {affine_b}) \\pmod{{26}}")
                        st.markdown("**최종 결과: `A(C(x))`**")
                        st.markdown("카이사르 암호화 결과에 아핀 암호화를 순차적으로 적용합니다.")

                        st.text_area("암호화 결과", encrypted, height=100)
            
            with col2:
                if st.button("🔓 조합 복호화", key="combined_dec"):
                    if 'combined_result' in st.session_state:
                        decrypted = combined_decrypt(st.session_state['combined_result'], 
                                                      caesar_shift, affine_a, affine_b)
                        st.markdown("---")
                        st.subheader("🔄 조합 복호화 과정")
                        st.markdown("암호화의 역순으로 복호화를 수행합니다.")
                        st.markdown("**1단계: 아핀 복호화**")
                        a_inv = mod_inverse(affine_a, 26)
                        st.latex(f"A^{{-1}}(y) = {a_inv}(y - {affine_b}) \\pmod{{26}}")
                        st.markdown("**2단계: 카이사르 복호화**")
                        st.latex(f"C^{{-1}}(z) = (z - {caesar_shift}) \\pmod{{26}}")
                        st.text_area("복호화 결과", decrypted, height=100)

with tab7:
    mt_chat, mt_log, mt_keys, mt_explain = st.tabs([
        "💬 채팅 시뮬레이션",
        "📜 암호화/블록체인 로그",
        "🔑 키 관리 (PBE)",
        "🧾 설명"
    ])

    if 'initialized_mini' not in st.session_state:
        st.session_state.initialized_mini = True
        st.session_state.a_priv_pem, st.session_state.a_pub_pem = crypto.generate_rsa_keys()
        st.session_state.a_priv_encrypted = crypto.encrypt_private_key(st.session_state.a_priv_pem, "password_a")
        st.session_state.a_priv_unlocked = None

        st.session_state.b_priv_pem, st.session_state.b_pub_pem = crypto.generate_rsa_keys()
        st.session_state.b_priv_encrypted = crypto.encrypt_private_key(st.session_state.b_priv_pem, "password_b")
        st.session_state.b_priv_unlocked = None

        st.session_state.messages = []
        st.session_state.logs = ["시뮬레이션이 시작되었습니다."]
        st.session_state.blockchain = bc.Blockchain(difficulty=2)
        try:
            p, g = crypto.generate_dh_params(2048)
        except Exception:
            p, g = 0, 2
        st.session_state.dh_p = p
        st.session_state.dh_g = g
        st.session_state.a_dh_priv, st.session_state.a_dh_pub = crypto.generate_dh_keypair(p, g)
        st.session_state.b_dh_priv, st.session_state.b_dh_pub = crypto.generate_dh_keypair(p, g)
        try:
            st.session_state.tcp_thread = start_tcp_server('0.0.0.0', 9632, st.session_state.blockchain, add_log)
        except Exception as e:
            add_log(f"TCP 서버 시작 실패: {e}")

    # --- 채팅 탭 ---
    with mt_chat:
        st.subheader("채팅 시뮬레이션")
        if not st.session_state.a_priv_unlocked or not st.session_state.b_priv_unlocked:
            st.warning("⚠️ 키가 잠겨있습니다. '키 관리 (PBE)' 탭에서 A와 B의 키를 언락(Unlock)하면 채팅을 이용할 수 있습니다.")

        col_a, col_b = st.columns(2)

        def send_message(sender_name, message, recipient_name):
            add_log(f"--- [START] {sender_name}가 {recipient_name}에게 전송 ---")
            add_log(f"1. 원본 메시지: '{message}'")
            msg_hash = crypto.get_message_hash(message)
            add_log(f"2. [무결성] 원본 메시지 해시(SHA-256) 생성: {msg_hash[:10]}...")

            sender_dh_priv = st.session_state.a_dh_priv if sender_name == "User A" else st.session_state.b_dh_priv
            recipient_dh_pub = st.session_state.b_dh_pub if recipient_name == "User B" else st.session_state.a_dh_pub
            if st.session_state.dh_p:
                session_key = crypto.derive_dh_shared(sender_dh_priv, recipient_dh_pub, st.session_state.dh_p)
                add_log("3. [키 교환] DH로부터 세션 키 파생 완료")
            else:
                session_key = get_random_bytes(32)
                add_log("3. [기밀성] (DH 실패) 일회용 AES-256 세션 키 생성 완료")

            ciphertext, tag, nonce = crypto.aes_encrypt(message, session_key)
            add_log(f"4. [기밀성] AES-GCM으로 메시지 암호화 완료: {ciphertext.hex()[:10]}...")

            sender_dh_pub = st.session_state.a_dh_pub if sender_name == "User A" else st.session_state.b_dh_pub
            message_bundle = {
                "sender": sender_name,
                "sender_dh_pub": str(sender_dh_pub),
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
                "tag": tag.hex(),
                "integrity_hash": msg_hash
            }
            add_log(f"6. 전송 패킷 생성 완료 (DH 공개키 + 암호문 + 해시)")

            sent = send_via_tcp(message_bundle, host='127.0.0.1', port=9632)
            if sent:
                add_log("7. [네트워크] TCP 릴레이로 전송 완료 (127.0.0.1:9632)")
            else:
                st.session_state.blockchain.add_transaction(message_bundle)
                new_block = st.session_state.blockchain.mine_pending_transactions()
                if new_block:
                    add_log(f"7. [블록체인] 로컬에 트랜잭션 추가 및 채굴 완료 (Index {new_block.index})")

            add_log(f"--- [RECV] {recipient_name}가 {sender_name}로부터 수신 ---")
            recipient_dh_priv = st.session_state.b_dh_priv if recipient_name == "User B" else st.session_state.a_dh_priv
            try:
                sender_dh_pub = int(message_bundle.get("sender_dh_pub", "0"))
                if st.session_state.dh_p:
                    decrypted_session_key = crypto.derive_dh_shared(recipient_dh_priv, sender_dh_pub, st.session_state.dh_p)
                    add_log("8. [키 교환] DH로부터 세션 키 파생 성공.")
                else:
                    add_log("8. [경고] DH 파라미터가 없어 세션 키 파생 불가")
                    st.session_state.messages.append((sender_name, recipient_name, "[수신 실패: 키 오류]", message_bundle))
                    return
            except Exception as e:
                add_log(f"8. [오류] DH 세션 키 파생 실패: {e}")
                st.session_state.messages.append((sender_name, recipient_name, "[수신 실패: 키 오류]", message_bundle))
                return

            decrypted_message = crypto.aes_decrypt(
                bytes.fromhex(message_bundle["ciphertext"]),
                bytes.fromhex(message_bundle["tag"]),
                bytes.fromhex(message_bundle["nonce"]),
                decrypted_session_key
            )
            add_log(f"9. [기밀성] AES-GCM으로 메시지 복호화 성공: '{decrypted_message}'")

            received_hash = crypto.get_message_hash(decrypted_message)
            if received_hash == message_bundle["integrity_hash"]:
                add_log("10. [무결성] 해시(SHA-256) 검증 성공. 메시지가 변조되지 않았습니다.")
            else:
                add_log(f"10. [경고!] 무결성 검증 실패! (원본: {message_bundle['integrity_hash'][:10]} vs 수신: {received_hash[:10]})")
                decrypted_message = "[메시지 변조 감지됨]"

            add_log("--- [END] 통신 사이클 완료 ---")
            st.session_state.messages.append((sender_name, recipient_name, decrypted_message, message_bundle))

        with col_a:
            st.subheader("User A")
            a_message = st.text_input("A가 B에게 보낼 메시지:", key="a_msg_input")
            if st.button("A ➡️ B 전송", key="a_send"):
                if a_message:
                    send_message("User A", a_message, "User B")
                    st.rerun()
                else:
                    st.warning("메시지를 입력하세요.")

        with col_b:
            st.subheader("User B")
            b_message = st.text_input("B가 A에게 보낼 메시지:", key="b_msg_input")
            if st.button("B ➡️ A 전송", key="b_send"):
                if b_message:
                    send_message("User B", b_message, "User A")
                    st.rerun()
                else:
                    st.warning("메시지를 입력하세요.")

        st.divider()
        st.subheader("채팅 기록 (복호화된 메시지)")
        chat_container = st.container()
        for sender, recipient, plaintext, _ in reversed(st.session_state.messages):
            if sender == "User A":
                chat_container.markdown(f"**[A ➡️ B]** {plaintext}")
            else:
                chat_container.markdown(f"**[B ➡️ A]** {plaintext}")

    # --- 로그 탭 ---
    with mt_log:
        st.header("📜 실시간 로그")
        st.info("메시지 전송 시 발생하는 암호화, 복호화, 해시, 블록체인 채굴 과정을 보여줍니다.")
        log_container = st.container()
        for log in reversed(st.session_state.logs):
            log_container.text(log)

        st.divider()
        st.header("🔗 블록체인 원장 (Message Ledger)")
        st.info("암호화된 메시지 트랜잭션이 저장된 블록체인입니다.")
        st.json(st.session_state.blockchain, expanded=False)
        if st.button("블록체인 무결성 검증"):
            is_valid = st.session_state.blockchain.is_chain_valid()
            if is_valid:
                st.success("✅ 블록체인 유효성 검증 성공!")
            else:
                st.error("❌ 블록체인 변조 감지!")

    # --- 키 관리 탭 ---
    with mt_keys:
        st.header("🔑 패스워드 기반 암호화(PBE) 키 관리")
        st.info("사용자의 RSA 개인키는 패스워드로 암호화되어 저장(PBE)됩니다. 채팅을 하려면 패스워드를 입력해 개인키를 메모리로 로드(Unlock)해야 합니다.")
        key_col_a, key_col_b = st.columns(2)
        with key_col_a:
            st.subheader("User A")
            st.text_area("A 공개키 (Public Key)", value=st.session_state.a_pub_pem.decode(), height=150, disabled=True)
            st.text_area("A 암호화된 개인키 (PBE Encrypted)", value=st.session_state.a_priv_encrypted, height=150, disabled=True)
            pass_a = st.text_input("User A 패스워드 ('password_a' 입력)", type="password", key="pass_a")
            if st.button("User A 키 Unlock", key="unlock_a"):
                unlocked_pem = crypto.decrypt_private_key(st.session_state.a_priv_encrypted, pass_a)
                if unlocked_pem:
                    st.session_state.a_priv_unlocked = unlocked_pem
                    st.success("User A 키가 성공적으로 복호화 및 로드되었습니다.")
                else:
                    st.error("User A 패스워드가 틀렸습니다.")
            if st.session_state.a_priv_unlocked:
                st.success("User A: 키 잠금 해제됨 (Ready)")

        with key_col_b:
            st.subheader("User B")
            st.text_area("B 공개키 (Public Key)", value=st.session_state.b_pub_pem.decode(), height=150, disabled=True)
            st.text_area("B 암호화된 개인키 (PBE Encrypted)", value=st.session_state.b_priv_encrypted, height=150, disabled=True)
            pass_b = st.text_input("User B 패스워드 ('password_b' 입력)", type="password", key="pass_b")
            if st.button("User B 키 Unlock", key="unlock_b"):
                unlocked_pem = crypto.decrypt_private_key(st.session_state.b_priv_encrypted, pass_b)
                if unlocked_pem:
                    st.session_state.b_priv_unlocked = unlocked_pem
                    st.success("User B 키가 성공적으로 복호화 및 로드되었습니다.")
                else:
                    st.error("User B 패스워드가 틀렸습니다.")
            if st.session_state.b_priv_unlocked:
                st.success("User B: 키 잠금 해제됨 (Ready)")

    # --- 설명 탭 ---
    with mt_explain:
        st.header("통신 흐름 설명 (User A 메시지 전송/수신 도식)")
        st.markdown("다음 다이어그램은 User A가 메시지를 암호화하여 전송하고, User B가 복호화하여 수신하는 전체 흐름을 보여줍니다.")
        dot = """
        digraph G {
          rankdir=LR;
          node [shape=box, style=rounded];
          A [label="User A\n(작성)"];
          B [label="User B\n(수신)"];
          DH [label="Diffie-Hellman\n(공개키 교환)"];
          SKEY [label="공유 세션 키\n(파생)\n(32 bytes)"];
          AES [label="AES-256-GCM\n(암호화)"];
          BUNDLE [label="전송 번들\n(ciphertext, nonce, tag, sender_dh_pub, hash)"];
          NET [label="네트워크/TCP\n(127.0.0.1:9632) / 릴레이"];
          BC [label="블록체인\n(트랜잭션으로 암호문 저장)"];
          VERIFY [label="SHA-256\n(무결성 검증)"];
          A -> DH -> B [label="1. 공개키 교환"];
          DH -> SKEY [label="2. 양측 파생(shared)"];
          SKEY -> AES [label="3. 메시지 암호화에 사용"];
          A -> AES -> BUNDLE -> NET -> BC -> B [label="4. 암호문 전송 및 기록"];
          B -> SKEY [label="5. 수신자가 동일한 공유키 파생"];
          B -> VERIFY [label="6. 해시 비교 (무결성)"];
          SKEY -> AES [label="7. 복호화 (AES-GCM)"];
        }
        """
        st.graphviz_chart(dot)

        st.markdown("### 단계별 설명")
        st.write(
            """
    1) A와 B는 서로 DH 공개키를 교환하여 같은 공유 세션 키를 파생합니다. (ECDH/DH)
    2) 파생된 공유키는 AES-256-GCM의 대칭 키로 사용됩니다.
    3) A는 메시지를 AES-256-GCM으로 암호화하고, ciphertext · nonce · tag · sender_dh_pub · 메시지 해시(SHA-256)를 묶어 전송 번들을 만듭니다.
    4) 전송 번들은 로컬 TCP 릴레이(127.0.0.1:9632)로 보내지며, 릴레이는 이를 블록체인 트랜잭션으로 기록하거나 바로 수신자에게 전달합니다.
    5) B는 A의 DH 공개키를 사용해 동일한 공유키를 파생한 뒤 AES로 복호화합니다.
    6) 복호화된 메시지의 SHA-256 해시를 비교하여 무결성을 확인합니다.
    """
        )

        st.markdown("---")
        st.markdown("참고: 현재 구현에서는 DH로 세션 키를 파생하고 TCP 릴레이(로컬)를 통해 번들을 전송합니다. 블록체인에는 암호화된 번들이 트랜잭션으로 저장됩니다.")

# -------------------- AES-OFB 탭 UI --------------------
with tab5:
    st.header("AES-OFB 대칭키 암복호화")
    with st.expander("ℹ️ OFB 모드란?"):
        st.markdown("""
        OFB(Output Feedback) 모드는 블록 암호를 스트림 암호처럼 사용하게 해주는 동작 모드입니다.
        - **암호화**: IV를 키로 암호화하여 첫 키 스트림 블록을 생성하고, 이를 평문 블록과 XOR하여 암호문을 만듭니다. 다음 키 스트림은 이전 **키 스트림 블록**을 다시 암호화하여 생성합니다.
        - **복호화**: 암호화와 동일한 과정으로 키 스트림을 생성하여 암호문과 XOR합니다.
        - **장점**: 암호문 한 비트의 오류가 평문의 해당 비트에만 영향을 미치므로 오류 전파가 적습니다.
        """)

    # 세션에 AES-OFB 키 보관
    if 'ofb_key' not in st.session_state:
        st.session_state['ofb_key'] = get_random_bytes(16)

    st.subheader("🔑 키 관리 (AES-128)")
    colk1, colk2 = st.columns([3,1])
    with colk1:
        st.code(base64.b64encode(st.session_state['ofb_key']).decode(), language='text')
    with colk2:
        if st.button("🔄 새 OFB 키 생성"):
            st.session_state['ofb_key'] = get_random_bytes(16)
            st.success("새 AES-OFB 키가 생성되었습니다.")

    ofb_plain = st.text_area("평문 입력", key="ofb_plain", placeholder="스트림 암호화할 메시지를 입력하세요.")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("🔒 OFB 암호화", key="ofb_encrypt_btn"):
            if ofb_plain:
                iv_b64, ct_b64 = aes_ofb_encrypt(ofb_plain, st.session_state['ofb_key'])
                st.session_state['ofb_iv'] = iv_b64
                st.session_state['ofb_ct'] = ct_b64
                st.markdown("---")
                st.subheader("🔄 암/복호화 과정 (XOR)")
                st.markdown("""
                1.  **키 스트림 생성**: `AES(Key, IV)`를 계산하여 첫 키 스트림 블록을 생성합니다.
                2.  **XOR 연산**: 생성된 키 스트림과 평문을 XOR하여 암호문을 생성합니다. `Ciphertext = Plaintext ⊕ Keystream`
                3.  복호화는 암호문에 동일한 키 스트림을 다시 XOR하여 평문을 복원합니다. `Plaintext = Ciphertext ⊕ Keystream`
                """)
                st.markdown("**IV (Base64)**")
                st.code(iv_b64, language='text')
                st.markdown("**Ciphertext (Base64)**")
                st.code(ct_b64, language='text')
            else:
                st.error("평문을 입력하세요.")
    with c2:
        if st.button("🔓 OFB 복호화", key="ofb_decrypt_btn"):
            if 'ofb_iv' in st.session_state and 'ofb_ct' in st.session_state:
                try:
                    pt = aes_ofb_decrypt(st.session_state['ofb_iv'], st.session_state['ofb_ct'], st.session_state['ofb_key'])
                    st.markdown("**복호화된 평문**")
                    st.code(pt, language='text')
                except Exception as e:
                    st.error(f"복호화 실패: {e}")
            else:
                st.error("먼저 암호문을 생성하세요.")

# -------------------- RSA 디지털 서명 탭 UI --------------------
with tab6:
    st.header("RSA 기반 디지털 서명")
    with st.expander("ℹ️ 디지털 서명이란?"):
        st.markdown("""
        디지털 서명은 메시지의 **무결성(Integrity)**과 **인증(Authentication)**, **부인 방지(Non-repudiation)**를 보장하는 핵심 기술입니다.
        - **서명 생성**: 송신자는 자신의 **개인키**로 메시지의 해시(SHA-512)를 암호화하여 서명을 생성합니다.
        - **서명 검증**: 수신자는 송신자의 **공개키**로 서명을 복호화하고, 직접 계산한 메시지 해시와 비교하여 서명을 검증합니다.
        
        개인키는 소유자만 가지고 있으므로, 공개키로 검증에 성공했다는 것은 해당 개인키 소유자가 서명했음을 증명합니다.
        """)

    # 키 생성 및 관리
    st.subheader("🔑 RSA 키 쌍 관리 (서명용)")
    if 'sig_private_key' not in st.session_state:
        if st.button("🔄 새 RSA 키 쌍 생성 (서명용)"):
            pub, priv = generate_rsa_keys()
            st.session_state['sig_public_key'] = pub
            st.session_state['sig_private_key'] = priv
            st.success("새로운 2048비트 RSA 키 쌍이 생성되었습니다.")
    
    if 'sig_private_key' in st.session_state:
        col1, col2 = st.columns(2)
        with col1:
            st.text_area("개인키 (서명용)", st.session_state['sig_private_key'], height=150)
        with col2:
            st.text_area("공개키 (검증용)", st.session_state['sig_public_key'], height=150)

    # 서명 생성 및 검증
    sig_message = st.text_area("서명할 메시지", key="sig_message", placeholder="서명을 생성할 원본 메시지를 입력하세요.")
    if st.button("✍️ 서명 생성 및 검증 실행"):
        if sig_message and 'sig_private_key' in st.session_state:
            # 서명 생성
            signature = rsa_sign(sig_message.encode(), st.session_state['sig_private_key'])
            st.markdown("---")
            st.subheader("✍️ 서명 생성 과정")
            st.markdown("""
            1.  **메시지 해시**: 원본 메시지에 대해 SHA-512 해시 함수를 적용하여 64바이트 다이제스트를 생성합니다.
            2.  **개인키로 암호화**: 생성된 다이제스트를 송신자의 **개인키**로 암호화(서명)합니다. 이 결과가 바로 디지털 서명입니다.
            
            이 서명은 오직 해당 개인키의 소유자만이 생성할 수 있습니다.
            """)

            st.markdown("**생성된 서명 (Base64)**")
            st.code(base64.b64encode(signature).decode(), language='text')

            # 즉시 검증
            is_valid = rsa_verify(sig_message.encode(), signature, st.session_state['sig_public_key'])
            st.markdown("**자체 검증 결과**")
            if is_valid:
                st.markdown("---")
                st.subheader("🔬 서명 검증 과정")
                st.markdown("""
                1.  **서명 복호화**: 수신된 서명을 송신자의 **공개키**로 복호화하여 원본 다이제스트(`H1`)를 얻습니다.
                2.  **메시지 재해시**: 함께 수신된 원본 메시지에 대해 동일한 SHA-512 해시 함수를 적용하여 새로운 다이제스트(`H2`)를 계산합니다.
                3.  **비교**: `H1`과 `H2`가 일치하는지 확인합니다. 일치하면 서명이 유효한 것입니다.
                """)

                st.success("✅ 서명이 유효합니다. (메시지 무결성 및 출처 확인)")
            else:
                st.error("❌ 서명이 유효하지 않습니다.")
        else:
            st.warning("메시지를 입력하고 키를 먼저 생성하세요.")
