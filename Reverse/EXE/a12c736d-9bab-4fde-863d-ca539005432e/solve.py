




with open("login.xlsx.enc", "rb") as f:
    enc = list(f.read())


key = "SUPERSECURE"

keys = list(key)

# print(enc)
for i in range (len(enc)):
    enc[i] -= ord(keys[i % len(keys)])
    enc[i] &= 0xff
    # print(enc[i], end = " ")

enc = bytes(enc)
print(enc)

with open("wwowo.xlsx", "wb") as out:
    out.write(enc)

# void encrypt(longlong param_1,ulonglong param_2)

# # {
# #   char local_17 [11];
# #   int local_c;
  
# #   builtin_strncpy(local_17,"SUPERSECURE",0xb);
# #   for (local_c = 0; (ulonglong)(longlong)local_c < param_2; local_c = local_c + 1) {
# #     *(char *)(param_1 + local_c) =
# #          local_17[(ulonglong)(longlong)local_c % 11] + *(char *)(param_1 + local_c);
# #   }
# #   return;
# # }

