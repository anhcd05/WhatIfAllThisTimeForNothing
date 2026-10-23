// op_not = sub_140001F60 (bản strip, IDA không có tên hàm)
void __fastcall sub_140001F60(const __m128i *a1, unsigned __int64 a2)
{
  const __m128i *v2; // rax
  unsigned __int64 v3; // r8
  __m128i v4; // xmm0
  char v5; // al
  unsigned __int64 v6; // r8
  char v7; // al

  if ( a2 != 0 )
  {
    if ( a2 - 1 <= 0xE )
    {
      v3 = 0;
    }
    else
    {
      v2 = a1;
      v3 = a2 & 0xFFFFFFFFFFFFFFF0uLL;
      do
      {
        v4 = _mm_loadu_si128(v2++);
        v2[-1] = _mm_xor_si128(v4, (__m128i)-1LL);
      }
      while ( v2 != (const __m128i *)&a1->m128i_i8[a2 & 0xFFFFFFFFFFFFFFF0uLL] );
      if ( a2 == v3 )
        return;
    }
    v5 = v3;
    a1->m128i_i8[v3] = ~a1->m128i_i8[v3];
    v6 = v3 + 1;
    v7 = a2 + ~v5;
    if ( v6 < a2 )
    {
      if ( (v7 & 1) == 0 || (a1->m128i_i8[v6] = ~a1->m128i_i8[v6], ++v6, v6 < a2) )
      {
        do
        {
          a1->m128i_i8[v6] = ~a1->m128i_i8[v6];
          a1->m128i_i8[v6 + 1] = ~a1->m128i_i8[v6 + 1];
          v6 += 2LL;
        }
        while ( v6 < a2 );
      }
    }
  }
}
