import random
import math

def lcm(a, b):
    return abs(a * b) // math.gcd(a, b)

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise Exception("L'inverse modulaire n'existe pas")
    else:
        return x % m

class Paillier:
    @staticmethod
    def generate_keys():
        p = 61  
        q = 53  
        n = p * q
        n_sq = n * n
        lam = lcm(p - 1, q - 1)
        g = n + 1
        u = pow(g, lam, n_sq)
        l_val = (u - 1) // n
        mu = mod_inverse(l_val, n)
        
        public_key = (n, g)
        private_key = (lam, mu)
        return public_key, private_key

    @staticmethod
    def encrypt(public_key, message):
        n, g = public_key
        n_sq = n * n
        if not (0 <= message < n):
            raise ValueError("Le message est trop grand pour l'espace de clé")
            
        r = random.randint(1, n - 1)
        while math.gcd(r, n) != 1:
            r = random.randint(1, n - 1)
            
        c = (pow(g, message, n_sq) * pow(r, n, n_sq)) % n_sq
        return c

    @staticmethod
    def decrypt(public_key, private_key, ciphertext):
        n, g = public_key
        lam, mu = private_key
        n_sq = n * n
        
        u = pow(ciphertext, lam, n_sq)
        l_val = (u - 1) // n
        message = (l_val * mu) % n
        return message

    @staticmethod
    def homomorphic_add(public_key, c1, c2):
        n, g = public_key
        n_sq = n * n
        return (c1 * c2) % n_sq
    
class RSA:
    @staticmethod
    def generate_keys():
        p, q = 79, 83  
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = mod_inverse(e, phi)
        return (e, n), (d, n)

    @staticmethod
    def sign(private_key, ciphertext_bulletin):
        d, n = private_key
        hash_val = hash(ciphertext_bulletin) % n
        signature = pow(hash_val, d, n)
        return signature

    @staticmethod
    def verify(public_key, ciphertext_bulletin, signature):
        e, n = public_key
        hash_val = hash(ciphertext_bulletin) % n
        decrypted_hash = pow(signature, e, n)
        return hash_val == decrypted_hash