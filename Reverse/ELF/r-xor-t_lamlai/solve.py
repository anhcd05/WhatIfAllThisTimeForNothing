




wanted_res = "C@qpl==Bppl@<=pG<>@l>@Blsp<@l@AArqmGr=B@A>q@@B=GEsmC@ArBmAGlA=@q"

hehe = []

for i in range(0, len(wanted_res)):
    hehe.append(ord(wanted_res[i]) ^ 3)

# print(hehe)
hehe2 = hehe[::-1]
# print(hehe2)

for i in range(0, len(hehe2)):
    tmp = (hehe2[i] & 0x7F) - 13
    print(chr(tmp), end = "")
