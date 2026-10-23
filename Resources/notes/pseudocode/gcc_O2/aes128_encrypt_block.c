__int64 __fastcall aes128_encrypt_block(const __m128i *a1, const __m128i *a2, __m128i *a3)
{
  const __m128i *v4; // rdi
  int v5; // r8d
  __m128i i; // xmm0
  __m128i *v7; // rcx
  int v8; // r10d
  __m128i *v9; // r11
  __int64 result; // rax
  __m128i *v11; // rbx
  char v12; // bp
  char v13; // al
  char v14; // dl
  char v15; // r13
  char v16; // r14
  __m128i v17; // [rsp+0h] [rbp-58h] BYREF
  __m128i v18; // [rsp+10h] [rbp-48h] BYREF
  char v19; // [rsp+20h] [rbp-38h] BYREF

  v4 = a1 + 1;
  v5 = 1;
  for ( i = _mm_xor_si128(_mm_loadu_si128(a2), _mm_loadu_si128(v4 - 1)); ; i = _mm_xor_si128(_mm_loadu_si128(v4++), v17) )
  {
    v7 = &v18;
    v17 = i;
    v8 = 0;
    v9 = &v18;
    do
    {
      for ( result = 0; result != 4; ++result )
        v9->m128i_i8[result] = AES_SBOX[v17.m128i_u8[(int)(result + 4 * (((_BYTE)v8 + (_BYTE)result) & 3))]];
      ++v8;
      v9 = (__m128i *)((char *)v9 + 4);
    }
    while ( v8 != 4 );
    if ( v5 == 10 )
      break;
    v11 = &v17;
    do
    {
      v12 = v7->m128i_i8[0];
      v13 = v7->m128i_i8[1];
      v7 = (__m128i *)((char *)v7 + 4);
      v11 = (__m128i *)((char *)v11 + 4);
      v14 = v7[-1].m128i_i8[14];
      v15 = v7[-1].m128i_i8[15];
      v16 = (2 * v13) ^ (v13 >> 7) & 0x1B;
      v11[-1].m128i_i8[12] = v16 ^ (2 * v12) ^ (v12 >> 7) & 0x1B ^ v15 ^ v14 ^ v13;
      v11[-1].m128i_i8[13] = (2 * v14) ^ (v14 >> 7) & 0x1B ^ v16 ^ v15 ^ v12 ^ v14;
      v11[-1].m128i_i8[14] = (2 * v15) ^ (v15 >> 7) & 0x1B ^ (2 * v14) ^ (v14 >> 7) & 0x1B ^ v15 ^ v12 ^ v13;
      v11[-1].m128i_i8[15] = (2 * v15) ^ (v15 >> 7) & 0x1B ^ (2 * v12) ^ (v12 >> 7) & 0x1B ^ v12 ^ v14 ^ v13;
    }
    while ( v7 != (__m128i *)&v19 );
    ++v5;
  }
  *a3 = _mm_xor_si128(_mm_loadu_si128(v4), v18);
  return result;
}
