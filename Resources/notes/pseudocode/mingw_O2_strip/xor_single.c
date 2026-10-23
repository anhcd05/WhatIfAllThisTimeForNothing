// xor_single = sub_140001CE0 (bản strip, IDA không có tên hàm)
void __fastcall sub_140001CE0(const __m128i *a1, unsigned __int64 a2, char a3)
{
  __m128i v3; // xmm1
  const __m128i *v4; // rax
  __m128i v5; // xmm1
  unsigned __int64 v6; // r9
  __m128i v7; // xmm1
  __m128i v8; // xmm0
  char v9; // al
  unsigned __int64 v10; // r9
  char v11; // al

  if ( a2 != 0 )
  {
    if ( a2 - 1 <= 0xE )
    {
      v6 = 0;
    }
    else
    {
      v3 = _mm_cvtsi32_si128(a3);
      v4 = a1;
      v5 = _mm_unpacklo_epi8(v3, v3);
      v6 = a2 & 0xFFFFFFFFFFFFFFF0uLL;
      v7 = _mm_shuffle_epi32(_mm_unpacklo_epi16(v5, v5), 0);
      do
      {
        v8 = _mm_loadu_si128(v4++);
        v4[-1] = _mm_xor_si128(v8, v7);
      }
      while ( v4 != (const __m128i *)&a1->m128i_i8[a2 & 0xFFFFFFFFFFFFFFF0uLL] );
      if ( a2 == v6 )
        return;
    }
    v9 = v6;
    a1->m128i_i8[v6] ^= a3;
    v10 = v6 + 1;
    v11 = a2 + ~v9;
    if ( v10 < a2 )
    {
      if ( (v11 & 1) == 0 || (a1->m128i_i8[v10] ^= a3, ++v10, v10 < a2) )
      {
        do
        {
          a1->m128i_i8[v10] ^= a3;
          a1->m128i_i8[v10 + 1] ^= a3;
          v10 += 2LL;
        }
        while ( v10 < a2 );
      }
    }
  }
}
