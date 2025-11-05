# insecure_example.py
# Exemplos: MD5, SHA1, AES-ECB, RSA 1024 bits, insecure random/hardcoded IV

import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import random  # insecure PRNG usage

def md5_hash(data):
    return hashlib.md5(data).hexdigest()  # MD5 (inseguro)

def sha1_hash(data):
    return hashlib.sha1(data).hexdigest()  # SHA1 (inseguro)

def aes_ecb_encrypt(key, plaintext):
    # Hardcoded IV not used in ECB, but key is hardcoded below
    cipher = AES.new(key, AES.MODE_ECB)  # AES-ECB insecure
    # padding simple (not secure)
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += chr(pad_len) * pad_len
    return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

def generate_small_rsa():
    # RSA 1024 bits (inseguro)
    key = RSA.generate(1024)
    return key

if __name__ == "__main__":
    msg = "dados sensiveis"

    print("MD5:", md5_hash(msg.encode()))
    print("SHA1:", sha1_hash(msg.encode()))

    # Hardcoded key - insecure
    hardcoded_key = b"0123456789abcdef"  # 16 bytes
    print("AES-ECB encrypted:", aes_ecb_encrypt(hardcoded_key, msg))

    rsa_key = generate_small_rsa()
    public_pem = rsa_key.publickey().export_key()
    print("RSA-1024 public key PEM (truncated):", public_pem[:60])

    # insecure PRNG usage
    rand_val = random.randint(0, 1000000)
    print("Insecure random value:", rand_val)
