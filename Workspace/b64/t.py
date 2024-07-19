import secrets
import string
import os
from hashlib import blake2b, sha256, sha512
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

def GenerateRandomString(Length=16):
    Characters = string.ascii_letters + string.digits
    Random = ''.join(secrets.choice(Characters) for _ in range(Length))
    return Random

def DeriveKey(UserID, DateCreated, Parameter, KeyLength=32):
    UserIDHash = sha512(UserID.encode('utf-8')).hexdigest()
    DateCreatedHash = sha256(DateCreated.encode('utf-8')).hexdigest()
    ParameterHash = sha256(Parameter.encode('utf-8')).hexdigest()
    Hash = blake2b(f"{UserIDHash}{DateCreatedHash}{ParameterHash}".encode('utf-8')).hexdigest()
    Key = PBKDF2(Hash, b'', dkLen=KeyLength, count=10000)
    return Key

def EncryptFile(input_file, output_file, Key):
    chunk_size = 64 * 1024  # 64 KB chunks
    IV = get_random_bytes(AES.block_size)
    Cipher = AES.new(Key, AES.MODE_GCM, nonce=IV)

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(IV)  # Write IV to the beginning of the output file
        while True:
            chunk = f_in.read(chunk_size)
            if len(chunk) == 0:
                break
            encrypted_chunk, tag = Cipher.encrypt_and_digest(chunk)
            f_out.write(encrypted_chunk)

def DecryptFile(input_file, output_file, Key):
    chunk_size = 64 * 1024  # 64 KB chunks

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        IV = f_in.read(AES.block_size)
        Cipher = AES.new(Key, AES.MODE_GCM, nonce=IV)
        while True:
            chunk = f_in.read(chunk_size)
            if len(chunk) == 0:
                break
            decrypted_chunk = Cipher.decrypt(chunk)
            f_out.write(decrypted_chunk)


UserID = "user123"
DateCreated = "2023-01-15"
Parameter = "example"
Key = DeriveKey(UserID, DateCreated, Parameter)

input_file = './Workspace/b64/dp.png'
encrypted_file = './Workspace/b64/encrypted_image.enc'
decrypted_file = './Workspace/b64/decrypted_image.png'

# Encrypt the image file
EncryptFile(input_file, encrypted_file, Key)
print(f"Image encrypted and saved as {encrypted_file}")

# Decrypt the encrypted file
DecryptFile(encrypted_file, decrypted_file, Key)
print(f"Image decrypted and saved as {decrypted_file}")


