void __fastcall op_rol8(const __m128i *a1, unsigned __int64 a2, char a3)
{
  int v4; // ecx
  const __m128i *v5; // rax
  __m128i v6; // xmm7
  unsigned __int64 v7; // r9
  __m128i v8; // xmm3
  __m128i v9; // xmm0
  __m128i v10; // xmm1
  __m128i v11; // xmm0
  __m128i v12; // xmm1
  char v13; // al
  unsigned __int64 v14; // r9
  char v15; // al

  if ( a2 != 0 )
  {
    v4 = a3 & 7;
    if ( a2 - 1 <= 0xE )
    {
      v7 = 0;
    }
    else
    {
      v5 = a1;
      v6 = _mm_cvtsi32_si128(v4);
      v7 = a2 & 0xFFFFFFFFFFFFFFF0uLL;
      v8 = _mm_srli_epi16((__m128i)-1LL, 8u);
      do
      {
        v9 = _mm_loadu_si128(v5++);
        v10 = v9;
        v11 = _mm_unpackhi_epi8(v9, (__m128i)0LL);
        v12 = _mm_unpacklo_epi8(v10, (__m128i)0LL);
        v5[-1] = _mm_or_si128(
                   _mm_packus_epi16(
                     _mm_and_si128(_mm_sll_epi16(v12, v6), v8),
                     _mm_and_si128(_mm_sll_epi16(v11, v6), v8)),
                   _mm_packus_epi16(
                     _mm_and_si128(_mm_srl_epi16(v12, (__m128i)(-(char)v4 & 7)), v8),
                     _mm_and_si128(_mm_srl_epi16(v11, (__m128i)(-(char)v4 & 7)), v8)));
      }
      while ( v5 != (const __m128i *)&a1->m128i_i8[a2 & 0xFFFFFFFFFFFFFFF0uLL] );
      if ( a2 == v7 )
        return;
    }
    v13 = v7;
    a1->m128i_i8[v7] = __ROL1__(a1->m128i_i8[v7], v4);
    v14 = v7 + 1;
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
