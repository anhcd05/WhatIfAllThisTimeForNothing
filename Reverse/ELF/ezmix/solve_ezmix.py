


def case1(ciphertext, key):
    return (ciphertext - key) & 0xff

def case2(ciphertext, key):
    return (ciphertext ^ key) & 0xff

def case3(ciphertext, key):
    return (((ciphertext << (key % 8))) & 0xff) | (((ciphertext >> (8 - (key % 8))) & 0xff)) & 0xff

with open("output.bin", "rb") as output:
    flag_encrypted = list(output.read())
# print(data)

with open("program.bin", "rb") as program:
    data2 = program.read()
# print(data2)

opcodes = []
keys = []
for i in range (len(data2) - 2, -1, -2):
    # print(data2[i + 1])
    # print(data2[i])
    keys.append(data2[i + 1])
    opcodes.append(data2[i])

# print(opcodes)
# print(keys)

# print(len(opcodes))
# print(len(flag_encrypted))
for i in range (len(opcodes) - 1):
    opcode = opcodes[i]
    key = keys[i]
    for j in range(len(flag_encrypted)):
        if (opcode == 1):
            flag_encrypted[j] = case1(flag_encrypted[j], key)
        elif (opcode == 2):
            flag_encrypted[j] = case2(flag_encrypted[j], key)
        else:
            flag_encrypted[j] = case3(flag_encrypted[j], key)
for c in flag_encrypted:
    print(chr(c), end = "")





# __int64 __fastcall sub_136C(__int64 data, int len_data, char *output)
# {
#   int vi_tri_chan; // eax
#   __int64 result; // rax
#   unsigned __int8 vi_tri_le; // [rsp+27h] [rbp-9h]
#   int v9; // [rsp+28h] [rbp-8h]
#   int i; // [rsp+2Ch] [rbp-4h]

#   v9 = 0;
#   for ( i = 0; ; i += 2 )
#   {
#     result = (unsigned int)i;
#     if ( i >= len_data )
#       break;
#     vi_tri_le = *(_BYTE *)(i + 1LL + data);
#     vi_tri_chan = *(unsigned __int8 *)(i + data);
#     if ( vi_tri_chan == '\x04' )
#     {
#       printf(format: "Insert your string: ");
#       fgets(s: output, n: 256, stream: stdin);
#       output[strcspn(s: output, reject: "\n")] = 0;
#       v9 = strlen(s: output);
#     }
#     else
#     {
#       if ( *(unsigned __int8 *)(i + data) > 4u )
#         goto LABEL_12;
#       switch ( vi_tri_chan )
#       {
#         case 3:
#           sub_1301(a1: (__int64 (__fastcall *)(_QWORD, _QWORD))sub_12C2, a2: vi_tri_le, a3: (__int64)output, a4: v9);
#           break;
#         case 1:
#           sub_1301(a1: (__int64 (__fastcall *)(_QWORD, _QWORD))sub_1289, a2: vi_tri_le, a3: (__int64)output, a4: v9);
#           break;
#         case 2:
#           sub_1301(a1: (__int64 (__fastcall *)(_QWORD, _QWORD))sub_12A7, a2: vi_tri_le, a3: (__int64)output, a4: v9);
#           break;
#         default:
# LABEL_12:
#           puts(s: "Error!");
#           exit(status: 1);
#       }
#     }
#   }
#   return result;
# }