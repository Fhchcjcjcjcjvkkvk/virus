import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY = b'54fdd053beb8dfd181d89f7f0d2dc09118f02892d559f438bc672a569fba7c24'  # 32 bytes
IV = b'74c8a9f3a3a346318de451a1b67ca298'  # 16 bytes

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
