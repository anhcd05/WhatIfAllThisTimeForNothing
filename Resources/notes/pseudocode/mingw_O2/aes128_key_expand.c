__int64 __fastcall aes128_key_expand(_QWORD *a1, _QWORD *a2)
{
  int v2; // r8d
  __int64 v5; // rdx
  __int64 i; // rdx
  __int64 result; // rax

  v2 = 1;
  v5 = a1[1];
  *a2 = *a1;
  a2[1] = v5;
  for ( i = 16; i != 176; i += 4 )
  {
    result = *(unsigned int *)((char *)a2 + i - 4);
    if ( (i & 0xF) == 0 )
    {
      result = (unsigned __int8)(v2 ^ AES_SBOX[BYTE1(result)])
             | (((unsigned __int8)AES_SBOX[BYTE2(result)]
               | (((unsigned __int8)AES_SBOX[BYTE3(result)] | ((unsigned __int8)AES_SBOX[(unsigned __int8)result] << 8)) << 8)) << 8);
      v2 = ((char)v2 >> 7) & 0x1B ^ (2 * v2);
    }
    *(_DWORD *)((char *)a2 + i) = _mm_cvtsi128_si32(
                                    _mm_xor_si128(
                                      _mm_cvtsi32_si128(result),
                                      _mm_cvtsi32_si128(*(_DWORD *)((char *)a2 + i - 16))));
  }
  return result;
}
