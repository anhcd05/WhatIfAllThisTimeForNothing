

key1 = "banana"
key2 = "strawberry"
key3 = "erwin"
key4 = "mandarin"
key5 = "melon"


enc = [   48,  43,  18,   6,  25,  78,  29,  94,  70,  29, 
   73,  82,   9,  16,  64,  93,  64,  92,  77,  78, 
   69,  21,  10,  13,  64,  83,  64,  84,  66,  82, 
   68,  90,  94,  81,  70,  12,  67,  25,  17,  18, 
   28,  83,  93,   6,  72,  64,  16,   4,  30,  77, 
   24,  95,  94,  70,  78,  84,  18,  94,  67,  76, 
   76,  70,  89,  93,  23,  88,  27,  17, 123]

for i in range(0, len(enc)):
    enc[i] ^= ord(key1[i % len(key1)])

for i in range(0, len(enc)):
    enc[i] ^= ord(key2[i % len(key2)])

for i in range(0, len(enc)):
    enc[i] ^= ord(key3[i % len(key3)])

for i in range(0, len(enc)):
    enc[i] ^= ord(key4[i % len(key4)])

for i in range(0, len(enc)):
    enc[i] ^= ord(key5[i % len(key5)])    


for i in range(len(enc)):
    print(chr(enc[i]), end = "")