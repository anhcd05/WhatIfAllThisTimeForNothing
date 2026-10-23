



key = [   24,  13,  21,  17,  10,  58,  49,  12,  25,  47, 
   71,  68, 109,  66,  55,  44,   0,  15,   0,   4, 
   23,  58,  26,  27,  42,  49,   4,  25,  59,  38, 
    1,  19,  23,  62,  10,  26,   4,   6,  31,  54, 
    2,   2,   7,  44,  62,  28,  62,   4,  24,  16, 
   44,  43,  31,  21,  10,  22,   4,   0,  31, 247]

wanted = "Please_input_the_correct_new_year_greetings_at_this_problem"

print(len(key))
print(len(wanted))

for i in range (len(wanted)):
    print(chr(key[i] ^ ord(wanted[i])), end = "")

