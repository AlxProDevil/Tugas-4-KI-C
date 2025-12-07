import os
import random
import math

def bytes_to_int(b):
    return int.from_bytes(b, 'big')

def int_to_bytes(i):
    length = math.ceil(i.bit_length() / 8)
    if length == 0:
        length = 1
    return i.to_bytes(length, 'big')

def manual_hash(data_bytes):
    digest_size = 32
    digest = bytearray(digest_size)

    for i, byte in enumerate(data_bytes):
        digest[i % digest_size] ^= byte
        
        digest[i % digest_size] = (digest[i % digest_size] + 1) % 256

    return int.from_bytes(digest, 'big')

def is_prime_miller_rabin(n, k=10):
    if n == 2 or n == 3: return True
    if n <= 1 or n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0: r += 1; d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def generate_prime(bits):
    while True:
        p = int.from_bytes(os.urandom(bits // 8), 'big')
        p |= (1 << (bits - 1)) | 1
        if is_prime_miller_rabin(p): return p

def mod_inverse(e, phi):
    d, x1, x2, y1 = 0, 0, 1, 1
    temp_phi = phi
    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi, e = e, temp2
        x = x2 - temp1 * x1
        y = d - temp1 * y1
        x2, x1 = x, x
        d, y1 = y1, y
    if temp_phi == 1: return d + phi

def generate_key_pair(bits):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q: q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while math.gcd(e, phi) != 1: e = random.randrange(3, phi, 2)
    d = mod_inverse(e, phi)
    return ((n, e), (n, d))

def encrypt(public_key, plaintext_bytes):
    n, e = public_key
    m = bytes_to_int(plaintext_bytes)
    if m >= n: raise ValueError("Pesan terlalu besar")
    return pow(m, e, n)

def decrypt(private_key, ciphertext_int):
    n, d = private_key
    m = pow(ciphertext_int, d, n)
    return int_to_bytes(m)

def sign(private_key, message_bytes):
    n, d = private_key
    
    m_hash_int = manual_hash(message_bytes)
    
    signature = pow(m_hash_int, d, n)
    return signature

def verify(public_key, message_bytes, signature):
    n, e = public_key
    
    recovered_hash_int = pow(signature, e, n)
    
    calculated_hash_int = manual_hash(message_bytes)
    
    return recovered_hash_int == calculated_hash_int