// op_add = sub_140003D80 (bản strip, IDA không có tên hàm)
unsigned __int64 __fastcall sub_140003D80(__int64 a1, unsigned __int64 a2, char a3)
{
  unsigned __int64 result; // rax
  unsigned __int64 v4; // r9
  __m128i v5; // xmm1
  __m128i v6; // xmm1
  __m128i v7; // xmm1
  unsigned __int64 v8; // rdx

  result = (unsigned int)a3;
  v4 = 0;
  v5 = _mm_cvtsi32_si128(result);
  v6 = _mm_unpacklo_epi8(v5, v5);
  v7 = _mm_shuffle_epi32(_mm_unpacklo_epi16(v6, v6), 0);
  if ( a2 != 0 )
  {
    if ( a2 >= 0x40 )
    {
      result = a2 & 0xFFFFFFFFFFFFFFC0uLL;
      do
      {
        *(__m128i *)(a1 + v4) = _mm_add_epi8(_mm_loadu_si128((const __m128i *)(a1 + v4)), v7);
        *(__m128i *)(a1 + v4 + 16) = _mm_add_epi8(_mm_loadu_si128((const __m128i *)(a1 + v4 + 16)), v7);
        *(__m128i *)(a1 + v4 + 32) = _mm_add_epi8(_mm_loadu_si128((const __m128i *)(a1 + v4 + 32)), v7);
        *(__m128i *)(a1 + v4 + 48) = _mm_add_epi8(_mm_loadu_si128((const __m128i *)(a1 + v4 + 48)), v7);
        v4 += 64LL;
      }
      while ( v4 < result );
    }
    if ( v4 < a2 )
    {
      result = v4 + a1;
      v8 = a2 - v4;
      do
      {
        *(_BYTE *)result++ += a3;
        --v8;
      }
      while ( v8 != 0 );
    }
  }
  return result;
}
