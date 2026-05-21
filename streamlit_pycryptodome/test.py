import string, random

LETTERS = string.ascii_uppercase + string.ascii_lowercase + " !@#$%^&*()_+|,."
EN_FREQ = {
    'A':8.167,'B':1.492,'C':2.782,'D':4.253,'E':12.702,'F':2.228,'G':2.015,'H':6.094,
    'I':6.966,'J':0.153,'K':0.772,'L':4.025,'M':2.406,'N':6.749,'O':7.507,'P':1.929,
    'Q':0.095,'R':5.987,'S':6.327,'T':9.056,'U':2.758,'V':0.978,'W':2.360,'X':0.150,
    'Y':1.974,'Z':0.074
}



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



def affineDecrypt(ciphertext, key1, key2, LETTERS):
    output = ""
    for y in ciphertext:
        if y in LETTERS:
            output += LETTERS[( (LETTERS.find(y) - key2) * modInv(key1, len(LETTERS)) ) % len(LETTERS)]
        else:
            output += y
    return output



def chiSquare_letters_and_digits(text):
    """문자(A–Z) + 숫자(0–9 균등분포)로 χ² 계산."""
    # 1) 문자 부분
    textLetters = [c for c in text.upper() if c in string.ascii_uppercase]
    N = len(textLetters)
    score = 0.0  # score 값 초기화
    if N > 0:
        obs = {ch: 0 for ch in string.ascii_uppercase}  # 딕셔너리 생성
        for c in textLetters:  # text 문자열 리스트에서 각 알파벳의 출현 회수 카운팅
            obs[c] += 1 # 딕셔너리 value 값 증가 (예시 : 'A':0 --> 'A':1로 증가
        for ch in string.ascii_uppercase:  # 모든 알파벳 문자에 대해서 ...
            expected = N * (EN_FREQ[ch] / 100.0) # expected 값 계산
            if expected > 0:
                diff = obs[ch] - expected
                score += (diff * diff) / expected

    # 2) 숫자 부분(균등)
    digits = [c for c in text.upper() if c.isdigit()]
    Nd = len(digits)
    if Nd > 0:
        expected_each = Nd / 10.0
        if expected_each > 0:
            obsD = {d: 0 for d in '0123456789'}
            for c in digits:
                obsD[c] += 1
            for d in '0123456789':
                diff = obsD[d] - expected_each
                score += (diff * diff) / expected_each

    return score if (N + Nd) > 0 else float('inf')

def affineBruteForceAttack_chiSquare(cipher, LETTERS):
    results = []
    for a in range(0, len(LETTERS)):
        if gcd(a, len(LETTERS)) != 1:
            continue
        for b in range(0, len(LETTERS)):
            dec = affineDecrypt(cipher, a, b, LETTERS)
            if dec is None:
                continue
            score = chiSquare_letters_and_digits(dec)
            results.append((score, a, b, dec))
    results.sort(key=lambda x: x[0])
    return results


if __name__ == "__main__":
    ciphertext = "#hbCzODIBtD|zIPO_rBhIB|_cDItD|zIPO_rBPtBOuDBCI&|OP|DBhoBCIhOD|OP+JB|hbCzODIBt_tODbtrB+DO%hIVtrB&+iBD^D|OIh+P|Bi&O&BoIhbBOuID&OtB^PVDBOuDoOrBi&b&JDrBz+&zOuhIPgDiB&||DttrB&+iBiPtIzCOPh+MBFOBP+Uh^UDtBPbC^DbD+OP+JBU&IPhztBbDOuhitrBOD|u+h^hJPDtrB&+iBCIhOh|h^tBOhBD+tzIDBOuDB|h+oPiD+OP&^PO_rBP+ODJIPO_rB&+iB&U&P^&cP^PO_BhoBP+ohIb&OPh+B&+iBiPJPO&^B&ttDOtB&J&P+tOBchOuBDaODI+&^B&+iBP+ODI+&^BIPtVtM"
    results = affineBruteForceAttack_chiSquare(ciphertext, LETTERS)
    best = results[0]
    print("Key1 (a) =", best[1], " Key2 (b) =", best[2])
    print(best[3])




