import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_key_and_iv():
    key = get_random_bytes(32)  # 256-bit AES key
    iv = get_random_bytes(16)   # 128-bit IV (AES block size)
    return key, iv

def encrypt_and_compress(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypts and compresses the data."""
    compressed = zlib.compress(data)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(compressed, AES.block_size))

def decrypt_and_decompress(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypts and decompresses the data."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(data), AES.block_size)
    return zlib.decompress(decrypted)
