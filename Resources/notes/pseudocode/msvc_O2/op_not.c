void __fastcall op_not(unsigned __int8 *b, unsigned __int64 n)
{
  unsigned __int64 v2; // r8
  __m128i si128; // xmm1
  unsigned __int8 *v4; // rax
  __int64 v5; // rdx

  v2 = 0;
  if ( n != 0 )
  {
    if ( n >= 0x40 )
    {
      si128 = _mm_load_si128((const __m128i *)&_xmm_ffffffffffffffffffffffffffffffff);
      do
      {
        *(__m128i *)&b[v2] = _mm_andnot_si128(_mm_loadu_si128((const __m128i *)&b[v2]), si128);
        *(__m128i *)&b[v2 + 16] = _mm_andnot_si128(_mm_loadu_si128((const __m128i *)&b[v2 + 16]), si128);
        *(__m128i *)&b[v2 + 32] = _mm_andnot_si128(_mm_loadu_si128((const __m128i *)&b[v2 + 32]), si128);
        *(__m128i *)&b[v2 + 48] = _mm_andnot_si128(_mm_loadu_si128((const __m128i *)&b[v2 + 48]), si128);
        v2 += 64LL;
      }
      while ( v2 < (n & 0xFFFFFFFFFFFFFFC0uLL) );
    }
    if ( v2 < n )
    {
      v4 = &b[v2];
      v5 = n - v2;
      do
      {
        *v4 = ~*v4;
        ++v4;
        --v5;
      }
      while ( v5 != 0 );
    }
  }
}
