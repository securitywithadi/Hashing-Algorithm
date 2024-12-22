#The below Python code helps with Hashing of Data. Used MD5, SHA1 & SHA256 for this example

import hashlib

def hash_comparison(data):
    md5_hash = hashlib.md5(data.encode()).hexdigest()
    sha1_hash = hashlib.sha1(data.encode()).hexdigest()
    sha256_hash = hashlib.sha256(data.encode()).hexdigest()
    return md5_hash, sha1_hash, sha256_hash

data = "SecureHashExample"
md5, sha1, sha256 = hash_comparison(data)

print(f"MD5: {md5}")
print(f"SHA-1: {sha1}")
print(f"SHA-256: {sha256}")
