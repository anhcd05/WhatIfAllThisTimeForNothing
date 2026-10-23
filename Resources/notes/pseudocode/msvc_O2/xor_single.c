void __fastcall xor_single(unsigned __int8 *b, unsigned __int64 n, char k)
{
  unsigned __int64 v3; // r9
  __m128i v4; // xmm1
  __m128i v5; // xmm1
  __m128i v6; // xmm1
  unsigned __int8 *v7; // rax
  __int64 v8; // rdx

  v3 = 0;
  v4 = _mm_cvtsi32_si128(k);
  v5 = _mm_unpacklo_epi8(v4, v4);
  v6 = _mm_shuffle_epi32(_mm_unpacklo_epi16(v5, v5), 0);
  if ( n != 0 )
  {
    if ( n >= 0x40 )
    {
      do
      {
        *(__m128i *)&b[v3] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)&b[v3]), v6);
        *(__m128i *)&b[v3 + 16] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)&b[v3 + 16]), v6);
        *(__m128i *)&b[v3 + 32] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)&b[v3 + 32]), v6);
        *(__m128i *)&b[v3 + 48] = _mm_xor_si128(_mm_loadu_si128((const __m128i *)&b[v3 + 48]), v6);
        v3 += 64LL;
      }
      while ( v3 < (n & 0xFFFFFFFFFFFFFFC0uLL) );
    }
    if ( v3 < n )
    {
      v7 = &b[v3];
      v8 = n - v3;
      do
      {
        *v7++ ^= k;
        --v8;
      }
      while ( v8 != 0 );
    }
  }
}
