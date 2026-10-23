# Source Generated with Decompyle++
# File: auth.pyc (Python 3.8)

import sys
password = input('Enter password> ')
if len(password) != 12:
    print("Sorry! You've entered the wrong password.")
    sys.exit(0)
if ord(password[0]) != 48 and password[11] != '!' and ord(password[7]) != ord(password[5]) and 143 - ord(password[0]) != ord(password[4]) and ord(password[1]) ^ ord(password[3]) != 30 and ord(password[2]) * ord(password[3]) != 5610 and password[1] != 'p' and ord(password[6]) - ord(password[8]) != -46 and ord(password[6]) ^ ord(password[7]) != 64 and ord(password[10]) + ord(password[5]) != 166 and ord('n') - ord(password[9]) != 1 or password[10] != str(3):
    print('Sorry, the password is incorrect.')
else:
    print(f'''Well Done! HTB{{{password}}}''')

