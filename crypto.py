import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

DEFAULT_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
KEY = bytes.fromhex(os.getenv("ICAP_SECRET_KEY", DEFAULT_KEY_HEX))

class CryptoError(Exception):
    pass
def decrypt_body(data: bytes) -> bytes:
    if not data.startswith(b"ENC1"):
        return data

    if len(data) < 32:
        raise CryptoError("payload too short")
    nonce = data[4:16]
    ciphertext_and_tag = data[16:]
    try:
        aes = AESGCM(KEY)
        return aes.decrypt(nonce, ciphertext_and_tag, None)
    except (InvalidTag, Exception) as e:
        raise CryptoError(f"decrypt failed: {e}") from e