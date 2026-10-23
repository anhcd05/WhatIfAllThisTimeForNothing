



with open ("secretMessage.enc", "rb") as f:
    cipher = f.read()


with open ("ididit", "wb") as out:


    previous = -1
    current = chr(int.from_bytes(cipher[0:1]))

    out.write(bytes([ord(current)]))
    viTriHienTai = 1

    while True:
        
        if viTriHienTai >= len(cipher):
            break

        previous = current
        current = chr(int.from_bytes(cipher[viTriHienTai: viTriHienTai + 1]))
        out.write(bytes([ord(current)]))


        if current == previous:
            viTriHienTai = viTriHienTai + 1
            count = int.from_bytes(cipher[viTriHienTai: viTriHienTai + 1])
            print(f"DEBUG WAS HERE {count}")
            viTriHienTai = viTriHienTai + 1
            for cnt in range (0, count):
                out.write(bytes([ord(previous)]))


            if count == 255:
                current = -99

        else:
            viTriHienTai = viTriHienTai + 1

