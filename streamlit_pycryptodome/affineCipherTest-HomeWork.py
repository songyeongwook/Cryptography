import string, random

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


if __name__ == "__main__":
    LETTERS = string.ascii_uppercase + string.ascii_lowercase + " !@#$%^&*()_+|,."

    key1 = random.choice(getReducedResidue(len(LETTERS)))
    print("Key1: ", key1)
    key2 = random.randrange(0, len(LETTERS))
    print("Key2: ", key2)
    if modInv(key1, len(LETTERS)):
        print("key1 (%d) has mulitplicative inverse!!!" % key1)

    print("LETTERS:", LETTERS)
    plaintext ="Computer security, or cybersecurity, is the practice of protecting computer systems, networks, and electronic data from threats like theft, damage, unauthorized access, and disruption. It involves implementing various methods, technologies, and protocols to ensure the confidentiality, integrity, and availability of information and digital assets against both external and internal risks."
    ciphertext = affineEncrypt(plaintext, key1, key2, LETTERS)
    print("ciphertext: ", ciphertext)

    output = affineDecrypt(ciphertext, key1, key2, LETTERS)
    print("plaintext: ", output)

