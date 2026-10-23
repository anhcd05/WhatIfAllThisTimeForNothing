

with open("secretMessage.enc", "rb") as f:
    cipher = f.read()

with open("flagPlaintext", "wb") as out:
    current = chr(int.from_bytes(cipher[0:1]))

    viTriHienTai = 1
    # print(current, end = "")
    out.write(bytes([ord(current)]))
    while True:
        if viTriHienTai >= len(cipher):
            break

        # for i in range(1, len(cipher)):
        count = 0
        previous = current

        current = chr(int.from_bytes(cipher[viTriHienTai: viTriHienTai + 1]))
        # print(current, end = "")
        out.write(bytes([ord(current)]))
        if current == previous:
            viTriHienTai = viTriHienTai + 1
            count = int.from_bytes(cipher[viTriHienTai: viTriHienTai + 1])
            viTriHienTai = viTriHienTai + 1
            
            # print(count)
            for cnt in range(count):
                out.write(bytes([ord(previous)]))
            
            if count == 255:
                current = None

        else:
            viTriHienTai = viTriHienTai + 1



