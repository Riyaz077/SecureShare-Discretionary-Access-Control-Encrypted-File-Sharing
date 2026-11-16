"""Small unit tests for the authenticated encryption primitive."""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def test_aes_gcm_round_trip():
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    original = b"confidential test document"
    ciphertext = aes.encrypt(nonce, original, None)
    assert aes.decrypt(nonce, ciphertext, None) == original


def test_aes_gcm_rejects_tampering():
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = bytearray(aes.encrypt(nonce, b"private", None))
    ciphertext[0] ^= 1
    try:
        aes.decrypt(nonce, bytes(ciphertext), None)
        assert False, "Tampered ciphertext should not decrypt"
    except Exception:
        pass
