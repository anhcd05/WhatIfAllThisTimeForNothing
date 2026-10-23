

from Crypto.Cipher import ChaCha20

key = ("BRAAAAAAAAAAAAAAAAAAAAAAAAAINS!!").encode()

with open("flag.txt.undead", "rb") as file:
    ct = file.read()

nonce = ("\x00" * 12).encode()

print(len(nonce))

cipher = ChaCha20.new(key=key, nonce=nonce)
plaintext = cipher.decrypt(ct)
print(plaintext)