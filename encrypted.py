"""
crypto_asset_demo.py
--------------------
Demo file intentionally using crypto assets that CBOMkit (CycloneDX CBOM)
should detect and flag.

Covers all 4 Crypto Asset categories:
  [A] Algorithm          - actual cipher/hash/KDF/signature algo calls
  [M] Related Material   - key generation, private/public key objects
  [P] Protocol           - TLS/SSL socket usage
  [C] Certificate        - X.509 cert loading/inspection

Intentional issues included:
  🚨 BROKEN : RC4, MD5, DES, SHA1 (broken by cryptanalysis)
  🚨 BROKEN : AES-ECB (leaks plaintext patterns)
  ⚠  QUANTUM: RSA-2048, DSA, DH (broken by quantum / deprecated)
  ✅ MODERN  : AES-GCM, ChaCha20-Poly1305, Ed25519, X25519, SHA-256, HKDF
"""

import os
import hashlib
import hmac
import ssl
import socket
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, dh, ec, ed25519, x25519, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate


# =============================================================================
# [A] ALGORITHM — 🚨 BROKEN: RC4 (stream cipher, cryptographically broken 2015)
# CBOMkit detects: algorithm, primitive=stream-cipher
# =============================================================================
def broken_rc4_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    RC4 stream cipher — broken. IETF banned via RFC 7465.
    CBOMkit flag: RC4 / stream-cipher / no known-safe parameterSet
    """
    cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext)


# =============================================================================
# [A] ALGORITHM — 🚨 BROKEN: DES (56-bit key, brute-forceable since 1999)
# CBOMkit detects: algorithm, primitive=block-cipher, parameterSet=56
# =============================================================================
def broken_des_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    DES with ECB mode — double broken (weak key + no IV chaining).
    CBOMkit flag: DES / block-cipher / mode=ECB / keySize=56
    """
    # DES key must be exactly 8 bytes (56-bit effective key strength)
    cipher = Cipher(algorithms.TripleDES(key), mode=modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad to 8-byte block boundary (naive — no PKCS7, another issue)
    padded = plaintext + b'\x00' * (8 - len(plaintext) % 8)
    return encryptor.update(padded) + encryptor.finalize()


# =============================================================================
# [A] ALGORITHM — 🚨 BROKEN: AES-ECB (leaks patterns, "penguin problem")
# CBOMkit detects: algorithm, primitive=block-cipher, mode=ECB
# =============================================================================
def broken_aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-128 in ECB mode — insecure. Identical plaintext blocks → identical
    ciphertext blocks. Never use for anything that matters.
    CBOMkit flag: AES / block-cipher / mode=ECB / keySize=128
    """
    cipher = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad to 16-byte block
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    return encryptor.update(padded) + encryptor.finalize()


# =============================================================================
# [A] ALGORITHM — 🚨 BROKEN: MD5 (collision attacks trivial since 2004)
# CBOMkit detects: algorithm, primitive=hash, parameterSet=128
# =============================================================================
def broken_md5_hash(data: bytes) -> str:
    """
    MD5 — collision attacks trivial since 2004. Never use for integrity/auth.
    CBOMkit flag: MD5 / hash / digest / parameterSet=128
    """
    return hashlib.md5(data).hexdigest()


# =============================================================================
# [A] ALGORITHM — 🚨 BROKEN: SHA-1 (SHAttered collision attack 2017, NIST deprecated)
# CBOMkit detects: algorithm, primitive=hash, parameterSet=160
# =============================================================================
def broken_sha1_hash(data: bytes) -> str:
    """
    SHA-1 — practical collision demonstrated (SHAttered, 2017).
    CBOMkit flag: SHA1 / hash / digest / parameterSet=160
    """
    return hashlib.sha1(data).hexdigest()


# =============================================================================
# [A] ALGORITHM — ⚠ QUANTUM-VULNERABLE: RSA-2048 keygen
# [M] MATERIAL  — private-key + public-key emitted
# CBOMkit detects: RSA-2048 / pke / keygen + private-key material
# =============================================================================
def quantum_vuln_rsa_keygen():
    """
    RSA-2048 key pair generation.
    Classical security: OK today. Quantum security: broken by Shor's algorithm.
    CBOMkit flag: RSA-2048 / pke / keygen  +  private-key / public-key material
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def quantum_vuln_rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    """
    RSA-OAEP encryption — quantum-vulnerable.
    CBOMkit flag: RSA-OAEP / pke / encrypt / padding=OAEP
    """
    return public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# =============================================================================
# [A] ALGORITHM — ⚠ QUANTUM-VULNERABLE: DSA (also NIST deprecated in FIPS 186-5)
# [M] MATERIAL  — private-key generated
# CBOMkit detects: DSA / signature / keygen + private-key material
# =============================================================================
def quantum_vuln_dsa_keygen():
    """
    DSA key generation — deprecated by NIST in FIPS 186-5 (2023).
    Also quantum-vulnerable via Shor's algorithm.
    CBOMkit flag: DSA / signature / keygen  +  private-key material
    """
    params = dsa.generate_parameters(key_size=2048, backend=default_backend())
    private_key = params.generate_private_key()
    return private_key


# =============================================================================
# [A] ALGORITHM — ⚠ QUANTUM-VULNERABLE: Diffie-Hellman key exchange
# [M] MATERIAL  — private-key generated
# CBOMkit detects: DH / key-agree / keygen + private-key material
# =============================================================================
def quantum_vuln_dh_keygen():
    """
    Classic Diffie-Hellman (MODP) key exchange — quantum-vulnerable.
    Should be replaced with X25519 or ML-KEM (NIST PQC standard).
    CBOMkit flag: DH / key-agree / keygen  +  private-key material
    """
    params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key = params.generate_private_key()
    return private_key


# =============================================================================
# [A] ALGORITHM — ⚠ WEAK KDF: PBKDF2-HMAC-MD5 (broken hash + low iterations)
# CBOMkit detects: PBKDF2 / kdf / keyderive  +  MD5 as inner hash
# =============================================================================
def weak_pbkdf2_md5(password: bytes, salt: bytes) -> bytes:
    """
    PBKDF2 with MD5 and dangerously low iterations.
    Double issue: broken hash + iteration count far below NIST SP 800-132 minimum (310,000 for SHA-256).
    CBOMkit flag: PBKDF2 / kdf  +  MD5 / hash (nested)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.MD5(),       # 🚨 broken hash as PRF
        length=32,
        salt=salt,
        iterations=1000,              # ⚠ way too low — min should be 310,000
        backend=default_backend()
    )
    return kdf.derive(password)


# =============================================================================
# [A] ALGORITHM — ✅ MODERN: AES-256-GCM (authenticated encryption)
# CBOMkit detects: AES-GCM / block-cipher / mode=GCM / keySize=256
# =============================================================================
def modern_aes_gcm_encrypt(plaintext: bytes) -> tuple:
    """
    AES-256-GCM — authenticated encryption with associated data (AEAD).
    This is what you should actually be using.
    CBOMkit flag: AES-GCM / block-cipher / mode=GCM / keySize=256
    """
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce — correct for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return key, nonce, ciphertext


# =============================================================================
# [A] ALGORITHM — ✅ MODERN: ChaCha20-Poly1305 (fast AEAD, no timing attacks)
# CBOMkit detects: ChaCha20-Poly1305 / stream-cipher / AEAD
# =============================================================================
def modern_chacha20_encrypt(plaintext: bytes) -> tuple:
    """
    ChaCha20-Poly1305 — preferred for constrained or non-AES-accelerated envs.
    CBOMkit flag: ChaCha20Poly1305 / stream-cipher + mac
    """
    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    return key, nonce, ciphertext


# =============================================================================
# [A] ALGORITHM — ✅ MODERN: Ed25519 (EdDSA signature, Curve25519)
# [M] MATERIAL  — private-key + public-key
# CBOMkit detects: Ed25519 / signature / keygen  +  private-key / public-key material
# =============================================================================
def modern_ed25519_sign(message: bytes) -> tuple:
    """
    Ed25519 — deterministic EdDSA signature, fast, no nonce reuse risk.
    CBOMkit flag: Ed25519 / signature / keygen  +  private-key material
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    signature = private_key.sign(message)
    return private_key, public_key, signature


# =============================================================================
# [A] ALGORITHM — ✅ MODERN: X25519 (ECDH key agreement, Curve25519)
# [M] MATERIAL  — private-key
# CBOMkit detects: X25519 / key-agree / keygen  +  private-key material
# =============================================================================
def modern_x25519_exchange() -> bytes:
    """
    X25519 Diffie-Hellman — constant-time, no invalid-curve attacks.
    Should replace classic DH for all new key exchange.
    CBOMkit flag: X25519 / key-agree / keygen  +  private-key material
    """
    alice_private = X25519PrivateKey.generate()
    bob_private = X25519PrivateKey.generate()
    shared_key = alice_private.exchange(bob_private.public_key())
    return shared_key


# =============================================================================
# [A] ALGORITHM — ✅ MODERN: HKDF-SHA256 (key derivation from shared secret)
# CBOMkit detects: HKDF / kdf / keyderive  +  SHA256 as inner hash
# =============================================================================
def modern_hkdf_sha256(input_key_material: bytes) -> bytes:
    """
    HKDF-SHA256 — extract-and-expand KDF, suitable for deriving session keys.
    CBOMkit flag: HKDF-SHA256 / kdf / keyderive
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"demo-context",
        backend=default_backend()
    )
    return hkdf.derive(input_key_material)


# =============================================================================
# [A] ALGORITHM — ✅ OK: HMAC-SHA256 (message authentication code)
# CBOMkit detects: HMAC-SHA256 / mac / tag
# =============================================================================
def ok_hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    HMAC-SHA256 — secure MAC. Fine for integrity verification.
    CBOMkit flag: HMAC-SHA256 / mac / tag
    """
    h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message)
    return h.finalize()


# =============================================================================
# [P] PROTOCOL — TLS socket (protocol asset)
# CBOMkit detects: TLS / protocol
# Note: using ssl.PROTOCOL_TLS_CLIENT with check_hostname=True is correct.
#       Downgrading to TLSv1.0/1.1 below is the intentional bad practice.
# =============================================================================
def protocol_tls_connection_good(hostname: str, port: int = 443):
    """
    TLS 1.3 connection — correct usage.
    CBOMkit flag: TLS / protocol / version=1.3
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2   # floor at 1.2 minimum
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    # (not actually connecting in demo — just showing the context setup)
    return ctx


def protocol_tls_connection_bad(hostname: str, port: int = 443):
    """
    ⚠ TLS with verification disabled — classic misconfiguration.
    CBOMkit flag: TLS / protocol  +  check_hostname=False / CERT_NONE = config risk
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False           # ⚠ disables hostname verification
    ctx.verify_mode = ssl.CERT_NONE     # 🚨 disables cert chain verification entirely
    return ctx


# =============================================================================
# [C] CERTIFICATE — X.509 cert loading (certificate asset)
# CBOMkit detects: certificate / X.509
# =============================================================================
def certificate_load_and_inspect(pem_data: bytes):
    """
    Load and inspect an X.509 certificate.
    CBOMkit flag: certificate / X.509 / related-crypto-material
    """
    cert = load_pem_x509_certificate(pem_data, default_backend())
    subject = cert.subject
    not_valid_after = cert.not_valid_after_utc
    signature_algo = cert.signature_hash_algorithm  # could itself be SHA1 = 🚨

    # 🚨 Common cert issue: checking if it uses a weak signature hash
    if isinstance(signature_algo, hashes.SHA1):
        print("[WARN] cert signed with SHA-1 — replace immediately")

    return cert


# =============================================================================
# BONUS: Hardcoded key — 🚨 secret management failure
# Not a crypto *algorithm* issue but CBOMkit / SAST tools flag this as
# related-crypto-material with hardcoded secret context.
# =============================================================================
HARDCODED_AES_KEY = b"0123456789abcdef"  # 🚨 hardcoded 128-bit key in source
HARDCODED_HMAC_SECRET = b"super_secret_hmac_key_do_not_ship"  # 🚨 same problem


def use_hardcoded_key(plaintext: bytes) -> bytes:
    """
    Using a hardcoded key — immediate secret management failure.
    Anyone with repo access has your key. Rotate immediately if this ships.
    CBOMkit / SAST flag: related-crypto-material / hardcoded-secret
    """
    cipher = Cipher(
        algorithms.AES(HARDCODED_AES_KEY),
        mode=modes.ECB(),   # 🚨 ECB on top of hardcoded key — double bad
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    padded = plaintext + b'\x00' * (16 - len(plaintext) % 16)
    return encryptor.update(padded) + encryptor.finalize()


# =============================================================================
# ENTRYPOINT — runs all functions to make them statically analysable
# =============================================================================
if __name__ == "__main__":
    sample_data = b"hello cbomkit, find my issues"
    sample_key_16 = os.urandom(16)
    sample_key_8  = os.urandom(8)   # DES key size

    print("=== 🚨 BROKEN ALGORITHMS ===")
    ct = broken_rc4_encrypt(sample_key_16, sample_data)
    print(f"RC4 ciphertext     : {ct.hex()[:32]}...")

    ct = broken_des_encrypt(sample_key_8, sample_data)
    print(f"DES-ECB ciphertext : {ct.hex()[:32]}...")

    ct = broken_aes_ecb_encrypt(sample_key_16, sample_data)
    print(f"AES-ECB ciphertext : {ct.hex()[:32]}...")

    h = broken_md5_hash(sample_data)
    print(f"MD5 hash           : {h}")

    h = broken_sha1_hash(sample_data)
    print(f"SHA-1 hash         : {h}")

    print("\n=== ⚠  QUANTUM-VULNERABLE ===")
    priv, pub = quantum_vuln_rsa_keygen()
    print(f"RSA-2048 key       : {pub.key_size}-bit public key generated")

    ct = quantum_vuln_rsa_encrypt(pub, b"secret")
    print(f"RSA-OAEP ciphertext: {ct.hex()[:32]}...")

    dsa_key = quantum_vuln_dsa_keygen()
    print(f"DSA key            : {dsa_key.key_size}-bit key generated")

    dh_key = quantum_vuln_dh_keygen()
    print(f"DH key             : generated ok")

    dk = weak_pbkdf2_md5(b"password123", os.urandom(16))
    print(f"PBKDF2-MD5 key     : {dk.hex()[:32]}...")

    print("\n=== ✅ MODERN / SAFE ===")
    key, nonce, ct = modern_aes_gcm_encrypt(sample_data)
    print(f"AES-256-GCM        : {ct.hex()[:32]}...")

    key, nonce, ct = modern_chacha20_encrypt(sample_data)
    print(f"ChaCha20-Poly1305  : {ct.hex()[:32]}...")

    priv, pub, sig = modern_ed25519_sign(sample_data)
    print(f"Ed25519 sig        : {sig.hex()[:32]}...")

    shared = modern_x25519_exchange()
    print(f"X25519 shared key  : {shared.hex()[:32]}...")

    derived = modern_hkdf_sha256(os.urandom(32))
    print(f"HKDF-SHA256        : {derived.hex()[:32]}...")

    mac = ok_hmac_sha256(sample_key_16, sample_data)
    print(f"HMAC-SHA256        : {mac.hex()[:32]}...")

    print("\n=== 🚨 HARDCODED KEY (secret management failure) ===")
    ct = use_hardcoded_key(b"do not do this  ")
    print(f"Hardcoded AES-ECB  : {ct.hex()[:32]}...")

    print("\n=== [P] TLS PROTOCOL ===")
    good_ctx = protocol_tls_connection_good("example.com")
    print(f"TLS (good config)  : min version = TLS 1.2, cert verify ON")
    bad_ctx  = protocol_tls_connection_bad("example.com")
    print(f"TLS (bad config)   : cert verify OFF, hostname check OFF")
