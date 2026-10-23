


with open("text_in.txt", "rb") as text_in:
    data_in = text_in.read()

with open("text_out.txt", "rb") as text_out:
    data_out = list(text_out.read())

# print(len(data_in))
# print(len(data_out))

import base64

standard = list(base64.b64encode(data_in))

# print(standard)
# print("DEBUG DEBUG DEBUG DEBUG DEBUG")
# print(data_out)


mapping_table = {}

for i in range (200):
    mapping_table[data_out[i]] = standard[i]

print(mapping_table)

with open("flag_out.txt", "rb") as f:
    enc = list(f.read())
tmp = ""
for i in range(len(enc)):
    print(chr(mapping_table[enc[i]]), end = "")
    tmp += chr(mapping_table[enc[i]])
print()
print(base64.b64decode(tmp))
