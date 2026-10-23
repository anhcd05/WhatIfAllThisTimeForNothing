// aes128_encrypt_block = sub_140002A20 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140002A20(const __m128i *a1, const __m128i *a2, __m128i *a3)
{
  int v3; // r11d
  __m128i v4; // xmm0
  const __m128i *i; // r10
  char *v6; // rcx
  int v7; // ebx
  __int64 *v8; // rsi
  __int64 result; // rax
  __m128i *v10; // rdi
  char v11; // bp
  char v12; // al
  char v13; // dl
  char v14; // r13
  char v15; // r14
  __m128i v16; // [rsp+0h] [rbp-68h] BYREF
  __int64 v17; // [rsp+10h] [rbp-58h] BYREF
  __int64 v18; // [rsp+18h] [rbp-50h] BYREF
  char v19; // [rsp+20h] [rbp-48h] BYREF

  v3 = 1;
  v4 = _mm_xor_si128(_mm_loadu_si128(a2), _mm_loadu_si128(a1));
  for ( i = a1 + 1; ; ++i )
  {
    v6 = (char *)&v17;
    v16 = v4;
    v7 = 0;
    v8 = &v17;
    do
    {
      for ( result = 0; result != 4; ++result )
        *((_BYTE *)v8 + result) = byte_14000FDE0[v16.m128i_u8[(int)(result + 4 * (((_BYTE)v7 + (_BYTE)result) & 3))]];
      ++v7;
      v8 = (__int64 *)((char *)v8 + 4);
    }
    while ( v7 != 4 );
    if ( v3 == 10 )
      break;
    v10 = &v16;
    do
    {
      v11 = *v6;
      v12 = v6[1];
      v6 += 4;
      v10 = (__m128i *)((char *)v10 + 4);
      v13 = *(v6 - 2);
      v14 = *(v6 - 1);
      v15 = (2 * v12) ^ (v12 >> 7) & 0x1B;
      v10[-1].m128i_i8[12] = v15 ^ (2 * v11) ^ (v11 >> 7) & 0x1B ^ v14 ^ v13 ^ v12;
      v10[-1].m128i_i8[13] = (2 * v13) ^ (v13 >> 7) & 0x1B ^ v15 ^ v14 ^ v11 ^ v13;
      v10[-1].m128i_i8[14] = (2 * v14) ^ (v14 >> 7) & 0x1B ^ (2 * v13) ^ (v13 >> 7) & 0x1B ^ v14 ^ v11 ^ v12;
      v10[-1].m128i_i8[15] = (2 * v14) ^ (v14 >> 7) & 0x1B ^ (2 * v11) ^ (v11 >> 7) & 0x1B ^ v11 ^ v13 ^ v12;
    }
    while ( v6 != &v19 );
    ++v3;
    v4 = _mm_xor_si128(_mm_loadu_si128(i), v16);
  }
  *a3 = _mm_xor_si128(_mm_loadu_si128(i), (__m128i)_mm_loadh_ps((const double *)&v18));
  return result;
}
