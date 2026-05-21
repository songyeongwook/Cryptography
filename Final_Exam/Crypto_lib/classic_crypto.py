import string
from typing import Tuple

EN_FREQ = {
    'A':8.167,'B':1.492,'C':2.782,'D':4.253,'E':12.702,'F':2.228,'G':2.015,'H':6.094,
    'I':6.966,'J':0.153,'K':0.772,'L':4.025,'M':2.406,'N':6.749,'O':7.507,'P':1.929,
    'Q':0.095,'R':5.987,'S':6.327,'T':9.056,'U':2.758,'V':0.978,'W':2.360,'X':0.150,
    'Y':1.974,'Z':0.074
}


def caesar_encrypt(text: str, shift: int) -> str:
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


def chi_square_score(text: str) -> float:
    text_letters = [c for c in text.upper() if c in string.ascii_uppercase]
    N = len(text_letters)
    if N == 0: return float('inf')

    observed = {ch: 0 for ch in string.ascii_uppercase}
    for c in text_letters:
        observed[c] += 1

    score = 0.0
    for ch in string.ascii_uppercase:
        expected = N * (EN_FREQ[ch] / 100.0)
        if expected > 0:
            diff = observed[ch] - expected
            score += (diff * diff) / expected
    return score


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a: int, m: int) -> int:
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    _, x, _ = extended_gcd(a, m)
    return (x % m + m) % m


def affine_encrypt(text: str, a: int, b: int) -> str:
    if gcd(a, 26) != 1:
        raise ValueError("'a'는 26과 서로소여야 합니다.")
    
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            x = ord(char) - ascii_offset
            encrypted = (a * x + b) % 26
            result += chr(encrypted + ascii_offset)
        else:
            result += char
    return result


def affine_decrypt(text: str, a: int, b: int) -> str:
    if gcd(a, 26) != 1:
        raise ValueError("'a'는 26과 서로소여야 합니다.")
    
    a_inv = mod_inverse(a, 26)
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            y = ord(char) - ascii_offset
            decrypted = (a_inv * (y - b)) % 26
            result += chr(decrypted + ascii_offset)
        else:
            result += char
    return result


def combined_encrypt(text: str, caesar_shift: int, affine_a: int, affine_b: int) -> str:
    caesar_result = caesar_encrypt(text, caesar_shift)
    return affine_encrypt(caesar_result, affine_a, affine_b)


def combined_decrypt(text: str, caesar_shift: int, affine_a: int, affine_b: int) -> str:
    affine_result = affine_decrypt(text, affine_a, affine_b)
    return caesar_decrypt(affine_result, caesar_shift)


def vigenere_encrypt(plaintext: str, key: str) -> str:
    result = []
    key_bytes = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    if not key_bytes:
        raise ValueError("키에 적어도 하나의 알파벳 문자가 필요합니다.")
    ki = 0
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = key_bytes[ki % len(key_bytes)]
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    result = []
    key_bytes = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    if not key_bytes:
        raise ValueError("키에 적어도 하나의 알파벳 문자가 필요합니다.")
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = key_bytes[ki % len(key_bytes)]
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)
