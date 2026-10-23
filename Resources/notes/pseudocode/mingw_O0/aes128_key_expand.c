__int64 __fastcall aes128_key_expand(__int64 *a1, __int64 *a2)
{
  __int64 v2; // rdx
  __int64 result; // rax
  int v4; // [rsp+2Fh] [rbp-11h]
  unsigned __int8 v5; // [rsp+33h] [rbp-Dh]
  int j; // [rsp+34h] [rbp-Ch]
  int i; // [rsp+38h] [rbp-8h]
  unsigned __int8 v8; // [rsp+3Fh] [rbp-1h]

  v8 = 1;
  v2 = a1[1];
  result = *a1;
  *a2 = *a1;
  a2[1] = v2;
  for ( i = 16; i <= 175; i += 4 )
  {
    v4 = *(_DWORD *)((char *)a2 + i - 4);
    result = i & 0xF;
    if ( (i & 0xF) == 0 )
    {
      v5 = v4;
      LOBYTE(v4) = v8 ^ AES_SBOX[BYTE1(v4)];
      BYTE1(v4) = AES_SBOX[BYTE2(v4)];
      BYTE2(v4) = AES_SBOX[HIBYTE(v4)];
      HIBYTE(v4) = AES_SBOX[v5];
      result = xt(a1: v8);
      v8 = result;
    }
    for ( j = 0; j <= 3; ++j )
    {
      result = (__int64)a2 + i + j;
      *(_BYTE *)result = *((_BYTE *)&v4 + j) ^ *((_BYTE *)a2 + i + j - 16);
    }
  }
  return result;
}
