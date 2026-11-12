import os
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto import decrypt_body, CryptoError, KEY

def encrypt_payload(plaintext: bytes, key: bytes = KEY) -> bytes:
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, None)
    return b"ENC1" + nonce + ct

def test_decrypt_plaintext_passthrough():
    data = b"Test message without encryption"
    assert decrypt_body(data) == data

def test_decrypt_valid_payload():
    secret = b"Test message"
    enc = encrypt_payload(secret)
    assert decrypt_body(enc) == secret

def test_decrypt_empty_payload():
    secret = b""
    enc = encrypt_payload(secret)
    assert decrypt_body(enc) == secret

def test_decrypt_short_container():
    with pytest.raises(CryptoError, match="payload too short"):
        decrypt_body(b"ENC1short")

def test_decrypt_wrong_key():
    wrong_key = os.urandom(32)
    enc = encrypt_payload(b"secret", key=wrong_key)
    with pytest.raises(CryptoError):
        decrypt_body(enc)

if __name__ == "__main__":
    test_decrypt_plaintext_passthrough()
    test_decrypt_valid_payload()
    test_decrypt_empty_payload()
    test_decrypt_short_container()
    test_decrypt_wrong_key()