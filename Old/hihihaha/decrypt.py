from Crypto.Cipher import AES
import hashlib
import base64

enc = '1KeGOcMvvKpPbxrNRdyqJmSGh3j+ZCvIT5RKk6lTBkSGBYSYrX7dy3Q/E8wVuQAXNFMs978T1A4qyx7EeX9fvg=='

key = b"ch@ng3Digit@lInf0rm@ti0n"
iv = b"Th3W0rldS@f3t0Ex"

def decrypt(encrypted,key,iv):   
  cipher = AES.new(key, AES.MODE_CBC, iv)
  decryptedtext = cipher.decrypt(base64.b64decode(encrypted))   # Base64 decode the ciphertext
  decryptedtextP = decryptedtext.rstrip(b'\0').decode("UTF-8", errors='ignore')  # remove the Zero padding
  return decryptedtextP

decrypted = decrypt(enc,key,iv)
print(decrypted) # 10203050