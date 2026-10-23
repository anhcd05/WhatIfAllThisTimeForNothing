void __fastcall op_rol8(const __m128i *a1, unsigned __int64 a2, char a3)
{
  int v4; // ecx
  unsigned __int64 v5; // rsi
  const __m128i *v6; // rax
  __m128i v7; // xmm7
  __m128i v8; // xmm3
  __m128i v9; // xmm0
  __m128i v10; // xmm1
  __m128i v11; // xmm0
  __m128i v12; // xmm1
  char v13; // al
  unsigned __int64 v14; // rsi
  char v15; // al

  if ( a2 != 0 )
  {
    v4 = a3 & 7;
    if ( a2 - 1 <= 0xE )
    {
      v5 = 0;
    }
    else
    {
      v5 = a2 & 0xFFFFFFFFFFFFFFF0LL;
      v6 = a1;
      v7 = _mm_cvtsi32_si128(v4);
      v8 = _mm_srli_epi16((__m128i)-1LL, 8u);
      do
      {
        v9 = _mm_loadu_si128(v6++);
        v10 = v9;
        v11 = _mm_unpackhi_epi8(v9, (__m128i)0LL);
        v12 = _mm_unpacklo_epi8(v10, (__m128i)0LL);
        v6[-1] = _mm_or_si128(
                   _mm_packus_epi16(
                     _mm_and_si128(_mm_sll_epi16(v12, v7), v8),
                     _mm_and_si128(_mm_sll_epi16(v11, v7), v8)),
                   _mm_packus_epi16(
                     _mm_and_si128(_mm_srl_epi16(v12, (__m128i)(-(char)v4 & 7)), v8),
                     _mm_and_si128(_mm_srl_epi16(v11, (__m128i)(-(char)v4 & 7)), v8)));
      }
      while ( v6 != (const __m128i *)&a1->m128i_i8[v5] );
      if ( a2 == v5 )
        return;
    }
    v13 = v5;
    a1->m128i_i8[v5] = __ROL1__(a1->m128i_i8[v5], v4);
    v14 = v5 + 1;
    v15 = a2 + ~v13;
    if ( v14 < a2 )
    {
      if ( (v15 & 1) == 0 || (a1->m128i_i8[v14] = __ROL1__(a1->m128i_i8[v14], v4), ++v14, v14 < a2) )
      {
        do
        {
          a1->m128i_i8[v14] = __ROL1__(a1->m128i_i8[v14], v4);
          a1->m128i_i8[v14 + 1] = __ROL1__(a1->m128i_i8[v14 + 1], v4);
          v14 += 2LL;
        }
        while ( v14 < a2 );
      }
    }
  }
}
