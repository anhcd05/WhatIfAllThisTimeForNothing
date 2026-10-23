


enc = bytes.fromhex("220c6a33204455fb390074013c4156d704316528205156d70b217c14255b6ce10837651234464e")

enc = list(enc)

len_enc = len(enc) # 39 % 8 = 7 => go to while loop

v3 = len_enc + 7 # 46
v32 = v3 >> 3 # 5 => loop 5 round

key = [0x88, 0x66, 0x44, 0x11, 0x77, 0x55, 0x22, 0x33]


# Về bản chất, nó chạy như này:
# vi tri thu 24 => su dung 0x88 tuc 0 (idx % 8 = 0)
# vi tri thu 25 => su dung 0x33 tuc 7 (idx % 8 = 1)
# vi tri thu 38 => su dung 0x44 tuc 2 (idx % 8 = 6)
# vi tri thu 37 => su dung 0x11 tuc 3 (idx % 8 = 5)
# vi tri thu 31 => su dung 0x66 tuc 1 (idx % 8 = 7)

# Thế nhưng code thật chạy từ cuối lên, vị trí idx = 38 thì nó chạy ở label 11 chứ đéo phải label 6
# Vậy nên là idx=38 % 8 = 6 => Chạy Label11 tức xor 0x33 vị trí key thứ 7
# idx=37 % 8 = 5 => Chạy Label10 xor 0x22 vị trí key thứ 6
# idx=36 % 8 = 4 => Chạy Label9 xor 0x55 vị trí key thứ 5
# Công thức nội suy như nào ? (idx % 8) + 1 ?



for idx in range(len_enc):
    enc[idx] ^= key[((idx % 8) + 1) % 8]
    print(chr(enc[idx]), end = "")


# print(len_enc)
# print(39 % 8)
# print(v3)
# print(v32)



