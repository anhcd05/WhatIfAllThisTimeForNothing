void __fastcall aes128_key_expand(const unsigned __int8 *key, unsigned __int8 *rk)
{
  __int128 v2; // xmm0
  unsigned __int8 v3; // di
  unsigned __int8 *v4; // rcx
  int v5; // r10d
  unsigned __int8 v6; // dl
  unsigned __int8 v7; // r9
  char v8; // r11
  unsigned __int8 v9; // bl
  unsigned __int8 t[4]; // [rsp+8h] [rbp+8h]

  v2 = *(_OWORD *)key;
  v3 = 1;
  v4 = rk + 1;
  v5 = 16;
  *(_OWORD *)rk = v2;
  do
  {
    *(_DWORD *)t = *(_DWORD *)(v4 + 11);
    v6 = t[3];
    if ( (v5 & 0xF) != 0 )
    {
      v9 = BYTE2(*(_DWORD *)(v4 + 11));
      v7 = BYTE1(*(_DWORD *)(v4 + 11));
      v8 = *(_DWORD *)(v4 + 11);
    }
    else
    {
      v7 = AES_SBOX[t[2]];
      v8 = v3 ^ AES_SBOX[t[1]];
      v9 = AES_SBOX[t[3]];
      v6 = AES_SBOX[t[0]];
      v3 = (27 * (v3 >> 7)) ^ (2 * v3);
    }
    v5 += 4;
    v4[15] = v8 ^ *(v4 - 1);
    v4[16] = *v4 ^ v7;
    v4[17] = v9 ^ v4[1];
    v4[18] = v6 ^ v4[2];
    v4 += 4;
  }
  while ( v5 < 176 );
}
