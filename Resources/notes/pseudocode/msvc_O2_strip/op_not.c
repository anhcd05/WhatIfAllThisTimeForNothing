// op_not = sub_140003E20 (bản strip, IDA không có tên hàm)
void __fastcall sub_140003E20(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v2; // r8
  __m128i si128; // xmm1
  _BYTE *v4; // rax
  unsigned __int64 v5; // rdx

  v2 = 0;
  if ( a2 != 0 )
  {
    if ( a2 >= 0x40 )
    {
      si128 = _mm_load_si128((const __m128i *)&xmmword_1400192C0);
      do
      {
        *(__m128i *)(a1 + v2) = _mm_andnot_si128(_mm_loadu_si128((const __m128i *)(a1 + v2)), si128);
        *(__m128i *)(a1 + v2 + 16) = _mm_andnot_si128(_mm_loadu_si128((const __m128i *)(a1 + v2 + 16)), si128);
        *(__m128i *)(a1 + v2 + 32) = _mm_andnot_si128(_mm_loadu_si128((const __m128i *)(a1 + v2 + 32)), si128);
        *(__m128i *)(a1 + v2 + 48) = _mm_andnot_si128(_mm_loadu_si128((const __m128i *)(a1 + v2 + 48)), si128);
        v2 += 64LL;
      }
      while ( v2 < (a2 & 0xFFFFFFFFFFFFFFC0uLL) );
    }
    if ( v2 < a2 )
    {
      v4 = (_BYTE *)(v2 + a1);
      v5 = a2 - v2;
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
