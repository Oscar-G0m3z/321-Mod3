from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse
from hashlib import sha256
import random
import os
import secrets

print("Task 1:")

def diffie_hellman_large_params(q, alpha):
    q = int(q.replace("\n", "").replace(" ", ""), 16)
    alpha = int(alpha.replace("\n", "").replace(" ", ""), 16)
    
    alice_private = random.randint(1, q - 1)
    bob_private = random.randint(1, q - 1)
    
    alice_public = pow(alpha, alice_private, q)
    bob_public = pow(alpha, bob_private, q)
    
    alice_shared_secret = pow(bob_public, alice_private, q)
    bob_shared_secret = pow(alice_public, bob_private, q)
    
    if alice_shared_secret != bob_shared_secret:
        raise ValueError("Key mismatch: Alice and Bob computed different shared secrets!")
    
    shared_key = SHA256.new(
        data=alice_shared_secret.to_bytes((alice_shared_secret.bit_length() + 7) // 8, byteorder='big')
    ).digest()[:16]
    
    return shared_key

def aes_encrypt(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext.decode()

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    return gcd, y1, x1 - (a // b) * y1

def modular_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError(f"No modular inverse exists for e={e} and phi={phi}.")
    return x % phi

message = "Hi Bob!"

q2 = """
B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61
6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF
ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0
A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
"""
alpha2 = """
A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31
266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4
D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A
D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
"""

print(q2, alpha2)
shared_key2 = diffie_hellman_large_params(q2, alpha2)
ciphertext2 = aes_encrypt(shared_key2, message)
decrypted_message2 = aes_decrypt(shared_key2, ciphertext2)


print(f"Alice's message: {message}")
print(f"Ciphertext sent to Bob: {ciphertext2.hex()}")
print(f"Decrypted message (at Bob): {decrypted_message2}")

print("__________________________________________________________")

def diffie_hellman_mitm(q, alpha, attacker_alpha=None):
    q = int(q.replace("\n", "").replace(" ", ""), 16) if isinstance(q, str) else q
    alpha = int(alpha.replace("\n", "").replace(" ", ""), 16) if isinstance(alpha, str) else alpha
    
    # Mallory overrides alpha if specified
    if attacker_alpha:
        alpha = attacker_alpha  
    
    alice_private = random.randint(1, q - 1)
    bob_private = random.randint(1, q - 1)

    # Compute normal public keys
    # Not used because of interception by Mallory

    # MITM Attack: Mallory forces YA and YB to q
    alice_fake_public = q  # YA -> q
    bob_fake_public = q  # YB -> q

    # Alice and Bob compute shared secret using Mallory's fake public keys
    alice_shared_secret = pow(alice_fake_public, alice_private, q)

    # Mallory knows the shared key in both cases
    shared_key = SHA256.new(
        data=alice_shared_secret.to_bytes((alice_shared_secret.bit_length() + 7) // 8, byteorder='big')
    ).digest()[:16]

    return shared_key

# Task 2 Diffie-Hellman MITM Attack
print("Task 2: Mallory's Attacks")
# Mallory replaces YA and YB with q
attacker_shared_key = diffie_hellman_mitm(q2, alpha2)
ciphertext = aes_encrypt(attacker_shared_key, message)
decrypted_message = aes_decrypt(attacker_shared_key, ciphertext)

print("Mallory's attack (YA and YB -> q):")
print("Ciphertext:", ciphertext.hex())
print("Decrypted message:", decrypted_message, "\n")

# Mallory replaces alpha with 1
attacker_shared_key_alpha1 = diffie_hellman_mitm(q2, alpha2, attacker_alpha=1)
ciphertext_alpha1 = aes_encrypt(attacker_shared_key_alpha1, message)
decrypted_message_alpha1 = aes_decrypt(attacker_shared_key_alpha1, ciphertext_alpha1)

print("Mallory's attack (alpha -> 1):")
print("Ciphertext:", ciphertext_alpha1.hex())
print("Decrypted message:", decrypted_message_alpha1, "\n")

print("__________________________________________________________")
# Task 3: RSA Key Exchange and Attack
def rsa_keygen(bits=2048):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return (n, e, d)

def rsa_encrypt(n, e, message):
    m = int.from_bytes(message.encode(), 'big')
    if m >= n:
        raise ValueError("Message too large for RSA modulus.")
    c = pow(m, e, n)
    return c

def rsa_decrypt(n, d, ciphertext):
    m = pow(ciphertext, d, n)
    message = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
    return message

print("Task 3: RSA Key Exchange and Attack")
n, e, d = rsa_keygen()
ciphertext_rsa = rsa_encrypt(n, e, message)
plaintext_rsa = rsa_decrypt(n, d, ciphertext_rsa)
print("Encrypted RSA message:", ciphertext_rsa)
print("Decrypted RSA message:", plaintext_rsa)

# RSA Key Generation
n, e, d = rsa_keygen()

# Alice chooses a secret value s
s = secrets.randbits(128)
c = pow(s, e, n)  # Encrypt s

# Mallory modifies c
factor = 3  # Chosen factor to manipulate s
c_prime = (c * pow(factor, e, n)) % n  # c' = c * factor^e mod n

# Bob decrypts c_prime
s_prime = pow(c_prime, d, n)  # Should be factor * s mod n

# Mallory can compute s_prime / factor to get s
s_recovered = s_prime // factor
assert s == s_recovered  # Mallory successfully retrieves s

# Alice derives a symmetric key
k = sha256(str(s_prime).encode()).digest()

# Alice encrypts a message with AES-CBC
message = "Hi Bob!"
iv = os.urandom(16)
cipher = AES.new(k, AES.MODE_CBC, iv)
padded_message = message.encode() + b" " * (16 - len(message) % 16)  # Padding
c0 = iv + cipher.encrypt(padded_message)

# Mallory, knowing s, derives k and decrypts
k_mallory = sha256(str(s).encode()).digest()
cipher_mallory = AES.new(k_mallory, AES.MODE_CBC, c0[:16])
message_recovered = cipher_mallory.decrypt(c0[16:])

# Ensure correct decoding by handling padding
message_recovered = message_recovered.rstrip(b" ")

print("Original message:", message)
print("Recovered by Mallory:", message_recovered.decode(errors='ignore'))
