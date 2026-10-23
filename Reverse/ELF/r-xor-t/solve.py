


enc = "C@qpl==Bppl@<=pG<>@l>@Blsp<@l@AArqmGr=B@A>q@@B=GEsmC@ArBmAGlA=@q"

out_input = [   0x7C, 0x40, 0x71, 0x70, 0x6C, 0x3D, 0x3D, 0x42, 0x70, 0x70, 
  0x6C, 0x40, 0x3C, 0x3D, 0x70, 0x47, 0x3C, 0x3E, 0x40, 0x6C, 
  0x3E, 0x40, 0x42, 0x6C, 0x73, 0x70, 0x3C, 0x40, 0x6C, 0x40, 
  0x41, 0x41, 0x72, 0x71, 0x6D, 0x47, 0x72, 0x3D, 0x42, 0x40, 
  0x41, 0x3E, 0x71, 0x40, 0x40, 0x42, 0x3D, 0x47, 0x45, 0x73, 
  0x6D, 0x43, 0x40, 0x41, 0x72, 0x42, 0x6D, 0x41, 0x47, 0x6C, 
  0x41, 0x3D, 0x40, 0x4E, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00]

enc = list(enc)
for i in range(len(enc)):
    enc[i] = ord(enc[i])
    if (enc[i] != out_input[i]):
        print(f"Sai o vi tri {i}")

#   if ( strlen(s: input) == 64 )
#   {
#     for ( i = 0; i <= 63; ++i )
#       rot[i] = (input[i] + 13) & 0x7F;

#     for ( j = 1; j <= 62; ++j )
#       result[j] = rot[63 - j];

#     for ( k = 0; k <= 64; ++k )
#       result2[k] = result[k] ^ 3;
#   }

# for ( i = 0; i <= 63; ++i )
#       rot[i] = (input[i] + 13) & 0x7F;
#     result[0] = byte_5555555580DF;
#     for ( j = 1; j <= 62; ++j )
#       result[j] = rot[63 - j];
#     byte_55555555813F = rot[0];
#     for ( k = 0; k <= 64; ++k )
#       result2[k] = result[k] ^ 3;

for i in range(64):
    enc[i] = enc[i] ^ 3

tmp_enc = [0] * 64

for i in range(63, -1, -1):
    tmp_enc[63 - i] = enc[i]

for i in range(64):
    for tmp_value in range(0, 256):
        if tmp_value == (tmp_enc[i] - 13):
            print(chr(tmp_value), end = "")



# for i in range(64):
#     print(chr(tmp_enc[i]), end = "")





