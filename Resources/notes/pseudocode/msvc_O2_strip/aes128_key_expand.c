// aes128_key_expand = sub_140001F00 (bản strip, IDA không có tên hàm)
char __fastcall sub_140001F00(__int128 *a1, _OWORD *a2)
{
  __int128 v2; // xmm0
  unsigned __int8 v3; // di
  char *v4; // rcx
  int v5; // r10d
  unsigned int v6; // edx
  char v7; // r9
  char v8; // r11
  char v9; // bl
  char result; // al
  unsigned int v11; // [rsp+8h] [rbp+8h]

  v2 = *a1;
  v3 = 1;
  v4 = (char *)a2 + 1;
  v5 = 16;
  *a2 = v2;
  do
  {
    v11 = *(_DWORD *)(v4 + 11);
    v6 = HIBYTE(v11);
    if ( (v5 & 0xF) != 0 )
    {
      v9 = BYTE2(*(_DWORD *)(v4 + 11));
      v7 = BYTE1(*(_DWORD *)(v4 + 11));
      v8 = *(_DWORD *)(v4 + 11);
    }
    else
    {
      v7 = byte_1400182D0[BYTE2(v11)];
      v8 = v3 ^ byte_1400182D0[BYTE1(v11)];
      v9 = byte_1400182D0[HIBYTE(v11)];
      LOBYTE(v6) = byte_1400182D0[(unsigned __int8)v11];
      v3 = (27 * (v3 >> 7)) ^ (2 * v3);
    }
    v5 += 4;
    v4[15] = v8 ^ *(v4 - 1);
    v4[16] = *v4 ^ v7;
    v4[17] = v9 ^ v4[1];
    result = v6 ^ v4[2];
    v4[18] = result;
    v4 += 4;
  }
  while ( v5 < 176 );
  return result;
}
