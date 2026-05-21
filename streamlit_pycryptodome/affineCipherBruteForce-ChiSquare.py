import string
from Caeser_Cipher.detectEnglish import isEnglish

def gcd(a, b):
    while(b!=0):
        temp = a % b
        a = b
        b = temp
    return abs(a)

def modInv(a, n):
    temp = n
    b, c = 1, 0
    while n:
        q, r = divmod(a, n)
        a, n, b, c = n, r, c, b-q*c
    if a == 1:
        return (temp + b) % temp
    raise ValueError("Not have Multiplicative Inverse!!!")

# 표준 영어 알파벳 빈도(%) — 합≈100
EN_FREQ = {
    'A':8.167,'B':1.492,'C':2.782,'D':4.253,'E':12.702,'F':2.228,'G':2.015,'H':6.094,
    'I':6.966,'J':0.153,'K':0.772,'L':4.025,'M':2.406,'N':6.749,'O':7.507,'P':1.929,
    'Q':0.095,'R':5.987,'S':6.327,'T':9.056,'U':2.758,'V':0.978,'W':2.360,'X':0.150,
    'Y':1.974,'Z':0.074
}

def affineEncrypt(plaintext, key1, key2, LETTERS):
    ciphertext = ""
    for x in plaintext:
        if x in LETTERS:
            ciphertext += LETTERS[ ((LETTERS.find(x) * key1) + key2) % len(LETTERS) ]
        else:
            ciphertext += x
    return ciphertext


def affineDecrypt(ciphertext, key1, key2, LETTERS):
    output = ""
    for y in ciphertext:
        if y in LETTERS:
            output += LETTERS[( (LETTERS.find(y) - key2) * modInv(key1, len(LETTERS)) ) % len(LETTERS)]
        else:
            output += y
    return output


def getCompleteResidue(m):
    return list(range(0,m))


def getReducedResidue(m):
    reducedResidueList = []
    for x in range(1,m):
        if gcd(x, m) == 1:
            reducedResidueList.append(x)
    return reducedResidueList


def eularPhi(m):
    return len(getReducedResidue(m))


def chiSquare_letters_only(text):
    """대소문자 무시, A–Z만으로 χ² 계산."""
    textLetters = [c for c in text.upper() if c in string.ascii_uppercase]
    N = len(textLetters)
    if N == 0:
        return float('inf')   # 무한대 값 리턴
    obs = {ch: 0 for ch in string.ascii_uppercase}  # 딕셔너리 생성
    for c in textLetters:  # text 문자열 리스트에서 각 알파벳의 출현 회수 카운팅
        obs[c] += 1 # 딕셔너리 value 값 증가 (예시 : 'A':0 --> 'A':1로 증가

    score = 0.0 # score 값 초기화
    for ch in string.ascii_uppercase:  # 모든 알파벳 문자에 대해서 ...
        expected = N * (EN_FREQ[ch] / 100.0) # expected 값 계산
        if expected > 0:
            diff = obs[ch] - expected
            score += (diff * diff) / expected
    return score   # Chi-square 값 계산

def affineBruteForceAttack_chiSquare(cipher: str, LETTERS):
    chiSquareCalculate = []
    key1List = getReducedResidue(len(LETTERS))
    key2List = getCompleteResidue(len(LETTERS))
    for key1 in key1List:
        for key2 in key2List:
            decryptedMessage = affineDecrypt(cipher, key1, key2, LETTERS)
            score = chiSquare_letters_only(decryptedMessage)
            chiSquareCalculate.append((score, key1, key2, decryptedMessage))
    chiSquareCalculate.sort(key=lambda x: x[0])  # score 값을 기준으로 정렬
    return chiSquareCalculate[:len(LETTERS)]

def affineBruteForceAttack_isEnglish(cipher: str, LETTERS):
    key1List = getReducedResidue(len(LETTERS))
    key2List = getCompleteResidue(len(LETTERS))
    for key1 in key1List:
        for key2 in key2List:
            decryptedMessage = affineDecrypt(cipher, key1, key2, LETTERS)
            if isEnglish(decryptedMessage):
                print("key1: %d, key2: %d \nPlaintext: %s" %(key1, key2, decryptedMessage))

if __name__ == "__main__":
    LETTERS = string.ascii_uppercase + string.ascii_lowercase + " !@#$%^&*()_+|,."

    ciphertext = "#hbCzODIBtD|zIPO_rBhIB|_cDItD|zIPO_rBPtBOuDBCI&|OP|DBhoBCIhOD|OP+JB|hbCzODIBt_tODbtrB+DO%hIVtrB&+iBD^D|OIh+P|Bi&O&BoIhbBOuID&OtB^PVDBOuDoOrBi&b&JDrBz+&zOuhIPgDiB&||DttrB&+iBiPtIzCOPh+MBFOBP+Uh^UDtBPbC^DbD+OP+JBU&IPhztBbDOuhitrBOD|u+h^hJPDtrB&+iBCIhOh|h^tBOhBD+tzIDBOuDB|h+oPiD+OP&^PO_rBP+ODJIPO_rB&+iB&U&P^&cP^PO_BhoBP+ohIb&OPh+B&+iBiPJPO&^B&ttDOtB&J&P+tOBchOuBDaODI+&^B&+iBP+ODI+&^BIPtVtM"
    print(affineBruteForceAttack_chiSquare(ciphertext, LETTERS))
    affineBruteForceAttack_isEnglish(ciphertext, LETTERS)