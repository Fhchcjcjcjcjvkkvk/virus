import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b'your_32_byte_super_secret_key_here!!'  # 32 bytes
IV = b'initialvector123'  # 16 bytes

def encrypt_and_compress(data: bytes) -> bytes:
    compressed = zlib.compress(data)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(pad(compressed, AES.block_size))
    return encrypted

def decrypt_and_decompress(data: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted = unpad(cipher.decrypt(data), AES.block_size)
    decompressed = zlib.decompress(decrypted)
    return decompressed
