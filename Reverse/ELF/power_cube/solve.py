





init = 0xDEADBEEFDEADBEEF


N = 312647161260980926

wanted = pow(init, pow(3, N, pow(2, 62)), pow(2, 64))

print(pow(pow(2, 64), 1, 1))

print(wanted)

byte_wanted = wanted.to_bytes(8, "little")

import hashlib

s = hashlib.sha256(byte_wanted).hexdigest()
print(s)

# flag = [0] * 64
# for i in range(0, 64, 2):
#     flag[i] = 
#     flag[i + 1] = 



# _BYTE *__fastcall gen_flag(__int64 hash)
# {
#   int i; // [rsp+14h] [rbp-Ch]
#   _BYTE *v4; // [rsp+18h] [rbp-8h]

#   v4 = malloc(size: 0x41u);
#   v4[64] = 0;
#   for ( i = 0; i <= 31; ++i )
#   {
#     v4[2 * i] = a0123456789abcd[*(i + hash) >> 4];
#     v4[2 * i + 1] = a0123456789abcd[*(i + hash) & 0xF];
#   }
#   return v4;
# }