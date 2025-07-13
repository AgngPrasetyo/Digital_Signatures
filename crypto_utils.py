def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

import base64
import random
from sympy import nextprime

def encrypt_rsa(message, d, n):
    b64 = base64.b64encode(message.encode()).decode()
    encrypted = []
    for char in b64:
        encrypted.append(str(mod_exp(ord(char), d, n)))
    return ",".join(encrypted)

def decrypt_rsa(cipher, e, n):
    parts = cipher.split(',')
    decrypted_b64 = ''
    for part in parts:
        decrypted_b64 += chr(mod_exp(int(part), e, n))
    try:
        return base64.b64decode(decrypted_b64).decode()
    except Exception:
        return "[signature or key might be incorrect]"

def sha256_hash(message):
    import hashlib
    return hashlib.sha256(message.encode()).hexdigest()

def generate_keys_auto():
   
    p = nextprime(random.randint(100, 300))
    q = nextprime(random.randint(301, 500))
    while p == q:
        q = nextprime(random.randint(301, 500))

    n = p * q
    phi = (p - 1) * (q - 1)

    
    e = nextprime(random.randint(3, phi // 2))
    while gcd(e, phi) != 1:
        e += 2

    d = mod_inverse(e, phi)
    return e, d, n
