



wanted1="58b4cb64f141e5c914640c5c8cc8e5d5"
wanted2="8a1828526galf607b8257cb552b0e6c8"
wanted3="z99za5c140689zc2d2a1052c8z5e4b9d"

plain1 = ""
plain2 = ""
plain3 = ""

for c in wanted1:
    tmp = ''
    if c == '4':
        tmp = 'a'
    elif c == 'd':
        tmp = '3'
    elif c == 'e':
        tmp = '7'
    else:
        tmp = c
    plain1 += tmp
print(plain1[::-1])

for c in wanted2:
    tmp = ''
    if c == 'f':
        tmp = '3'
    elif c == 'l':
        tmp = 'd'
    elif c == 'g':
        tmp = '9'
    else:
        tmp = c
    plain2 += tmp
print(plain2[::-1])

for c in wanted3:
    tmp = ''
    if c == '2':
        tmp = 'f'
    elif c == 'b':
        tmp = '7'
    elif c == 'z':
        tmp = '3'
    else:
        tmp = c
    plain3 += tmp
print(plain3[::-1])

nl = [0, 6, 17, 14, 1, 18, 16, 7, 11, 13, 8, 12, 2, 3, 0, 15, 4, 0, 9, 5, 0, 0, 10, 0, 0]


# h1 = "20231114"
#       61783450

# h2 = "fL46"
#       GHAB

# h3 = "Dec0d3"
#       DFC2E9   

# Final = 001112233446cDdefL

passwd = ""
pwbody = (' ' + passwd).split('')
print(pwbody)

i = 0
while i < 24:
    print(pwbody[nl[i]], end = " ")
    i = i + 1
    print(pwbody[nl[i]], end = " ")
    i = i + 1
    print(pwbody[nl[i]], end = " ")
    i = i + 1


