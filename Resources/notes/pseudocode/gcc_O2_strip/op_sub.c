// op_sub = sub_2920 (bản strip, IDA không có tên hàm)
void __fastcall sub_2920(const __m128i *a1, unsigned __int64 a2, char a3)
{
  __m128i v4; // xmm1
  const __m128i *v5; // rax
  __m128i v6; // xmm1
  unsigned __int64 v7; // rdx
  __m128i v8; // xmm1
  __m128i v9; // xmm0
  char v10; // al
  unsigned __int64 v11; // rdx
  char v12; // al

  if ( a2 != 0 )
  {
    if ( a2 - 1 <= 0xE )
    {
      v7 = 0;
    }
    else
    {
      v4 = _mm_cvtsi32_si128(a3);
      v5 = a1;
      v6 = _mm_unpacklo_epi8(v4, v4);
      v7 = a2 & 0xFFFFFFFFFFFFFFF0LL;
      v8 = _mm_shuffle_epi32(_mm_unpacklo_epi16(v6, v6), 0);
      do
      {
        v9 = _mm_loadu_si128(v5++);
        v5[-1] = _mm_sub_epi8(v9, v8);
      }
      while ( v5 != (const __m128i *)&a1->m128i_i8[a2 & 0xFFFFFFFFFFFFFFF0LL] );
      if ( a2 == v7 )
        return;
    }
    v10 = v7;
    a1->m128i_i8[v7] -= a3;
    v11 = v7 + 1;
    v12 = a2 + ~v10;
    if ( v11 < a2 )
    {
      if ( (v12 & 1) == 0 || (a1->m128i_i8[v11] -= a3, ++v11, v11 < a2) )
      {
        do
        {
          a1->m128i_i8[v11] -= a3;
          a1->m128i_i8[v11 + 1] -= a3;
          v11 += 2LL;
        }
        while ( v11 < a2 );
      }
    }
  }
}
