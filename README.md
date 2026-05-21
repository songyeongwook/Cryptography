# Cryptography

PyCryptodome와 Streamlit 기반으로 구현한 암호학 학습 및 시뮬레이션 프로젝트입니다.  
AES, RSA, SHA-512, Diffie-Hellman, AES-GCM, 블록체인 기반 Mini-Telegram 기능 등을 구현하였습니다.

GitHub Repository:  
:contentReference[oaicite:0]{index=0}

---

# 프로젝트 소개

본 프로젝트는 다양한 현대 암호 기술과 고전 암호 알고리즘을 직접 구현하고,
암호화 과정과 동작 원리를 시각적으로 학습할 수 있도록 제작한 프로젝트입니다.

사용자는 Streamlit 기반 UI를 통해:
- AES 암호화
- RSA 암호화
- 디지털 서명
- 고전 암호
- Mini Telegram
- 블록체인 기반 메시지 저장

등의 기능을 직접 실습할 수 있습니다.

---

# 주요 기능

## 현대 암호 시스템
- AES-CBC 암/복호화
- AES-OFB 암/복호화
- SHA-512 + AES 기반 무결성 검증
- RSA 공개키 암호화
- RSA 디지털 서명
- AES-GCM 인증 암호

---

## 고전 암호 시스템
- 카이사르 암호
- 아핀 암호
- 비즈네르 암호
- 조합 암호
- 카이제곱 통계 기반 복호화

---

## Mini-Telegram
- Diffie-Hellman 기반 세션키 생성
- AES-GCM 기반 안전한 메시지 전송
- 블록체인 기반 메시지 저장
- PoW 기반 채굴 시뮬레이션

---

# 프로젝트 구조

```plaintext
Cryptography/
│
├── ui/
│   └── ui.py
│       └── Streamlit 기반 메인 UI
│
├── crypto_lib/
│   │
│   ├── modern_crypto_lib.py
│   │   └── AES, RSA, AES-GCM, 디지털 서명 구현
│   │
│   └── classic_crypto.py
│       └── 카이사르, 아핀, 비즈네르 암호 구현
│
├── util/
│   │
│   ├── crypto_utils.py
│   │   └── PBE, AES-GCM, DH 키 관리
│   │
│   └── blockchain_utils.py
│       └── 블록체인 및 채굴 기능 구현
│
├── 결과 보고서/
│   └── 프로젝트 결과 보고서 및 실행 자료
│
├── README.md
│
└── requirements.txt
```

---

# 사용 기술

## Language
- Python

## Framework
- Streamlit

## Cryptography
- PyCryptodome
- AES
- RSA
- SHA-512
- AES-GCM
- Diffie-Hellman

## Network / Security
- TCP Socket
- Blockchain
- PoW(Proof of Work)

---

# 구현 특징

- Streamlit 기반 직관적인 UI 구성
- AES 암호화 과정 시각화
- st.latex 기반 수학 공식 출력
- RSA 디지털 서명 구현
- AES-GCM 기반 인증 암호 구현
- Diffie-Hellman 키 교환 구현
- 블록체인 기반 메시지 저장 및 채굴 구현
- TCP 기반 메시지 전달 시뮬레이션

---

# 실행 방법

## 라이브러리 설치

```bash
pip install -r requirements.txt
```

---

## Streamlit 실행

```bash
streamlit run ui.py
```

---

# 학습 내용

본 프로젝트를 통해 다음 내용을 학습하였습니다.

- 대칭키 암호 구조
- 공개키 암호 구조
- AES 동작 원리
- RSA 암호화 및 디지털 서명
- SHA 기반 무결성 검증
- Diffie-Hellman 키 교환
- AES-GCM 인증 암호
- 블록체인 및 PoW 구조
- Streamlit 기반 UI 개발

---

# 참고 사항

본 프로젝트는 암호학 학습 및 시뮬레이션 목적의 프로젝트입니다.  
실제 서비스 환경에서는 추가적인 보안 검증이 필요합니다.
