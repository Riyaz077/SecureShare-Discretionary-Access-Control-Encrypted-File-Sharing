from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def test_aes_gcm_round_trip():
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    original = b"SecureShare smoke test"
    encrypted = AESGCM(key).encrypt(nonce, original, None)
    assert AESGCM(key).decrypt(nonce, encrypted, None) == original
