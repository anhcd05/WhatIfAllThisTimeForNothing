

# with open("secretMessage.enc", "rb") as file:
#     full_encrypted = file.read()    

full_plaintext = b"AAAABBBCC"

previous_char = -1
countLoopChar = 0

index = 0

while True:
    
    if index >= len(full_plaintext):
        break

    current_char = full_plaintext[index]
    index = index + 1

    if current_char == previous_char:
        countLoopChar = 0
        while True:
            if current_char != previous_char:
                print(f"{countLoopChar} wowowo {current_char}")
                current_char = full_plaintext[index]
                break
            else:
                countLoopChar = countLoopChar + 1
                current_char = full_plaintext[index]
                break

    else:
        previous_char = current_char

