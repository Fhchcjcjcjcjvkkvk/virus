from Crypto.Random import get_random_bytes

iv = get_random_bytes(16)
print(f"IV: {iv.hex()}")
