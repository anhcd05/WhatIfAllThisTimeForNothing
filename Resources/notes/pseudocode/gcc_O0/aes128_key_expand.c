__int64 __fastcall aes128_key_expand(__int64 *a1, __int64 *a2)
{
  __int64 v2; // rdx
  __int64 result; // rax
  int v5; // [rsp+1Fh] [rbp-11h]
  unsigned __int8 v6; // [rsp+23h] [rbp-Dh]
  int j; // [rsp+24h] [rbp-Ch]
  int i; // [rsp+28h] [rbp-8h]
  unsigned __int8 v9; // [rsp+2Fh] [rbp-1h]

  v9 = 1;
  v2 = a1[1];
  result = *a1;
  *a2 = *a1;
  a2[1] = v2;
  for ( i = 16; i <= 175; i += 4 )
  {
    v5 = *(_DWORD *)((char *)a2 + i - 4);
    result = i & 0xF;
    if ( (i & 0xF) == 0 )
    {
      v6 = v5;
      LOBYTE(v5) = v9 ^ AES_SBOX[BYTE1(v5)];
      BYTE1(v5) = AES_SBOX[BYTE2(v5)];
      BYTE2(v5) = AES_SBOX[HIBYTE(v5)];
      HIBYTE(v5) = AES_SBOX[v6];
      result = xt(a1: v9);
      v9 = result;
    }
    for ( j = 0; j <= 3; ++j )
    {
      result = (__int64)a2 + i + j;
      *(_BYTE *)result = *((_BYTE *)&v5 + j) ^ *((_BYTE *)a2 + i + j - 16);
    }
  }
  return result;
}
