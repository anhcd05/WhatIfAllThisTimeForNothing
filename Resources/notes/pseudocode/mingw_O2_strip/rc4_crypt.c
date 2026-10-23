// rc4_crypt = sub_1400022E0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_1400022E0(__int64 a1, unsigned __int64 a2, _BYTE *a3, __int64 a4)
{
  __m128i v4; // xmm2
  __m128i v5; // xmm5
  char *v8; // r10
  __m128i *v9; // rax
  __m128i v10; // xmm9
  __m128i v11; // xmm8
  __m128i v12; // xmm7
  __m128i v13; // xmm6
  __m128i v14; // xmm3
  __m128i v15; // xmm0
  __m128i v16; // xmm4
  __m128i v17; // xmm3
  __m128i v18; // xmm1
  __m128i v19; // xmm3
  __m128i v20; // xmm0
  __m128i v21; // xmm1
  __m128i v22; // xmm3
  __m128i v23; // xmm0
  __m128i v24; // xmm3
  unsigned __int64 v25; // rcx
  unsigned int v26; // r8d
  unsigned __int64 v27; // rax
  char v28; // r11
  __int64 result; // rax
  _BYTE *v30; // r9
  int v31; // r10d
  int v32; // r8d
  char v33; // al
  _BYTE v34[256]; // [rsp+0h] [rbp-158h] BYREF
  __int128 v35; // [rsp+100h] [rbp-58h] BYREF

  v4 = _mm_loadu_si128((const __m128i *)&xmmword_14000FEE0);
  v5 = _mm_srli_epi16((__m128i)-1LL, 8u);
  v8 = v34;
  v9 = (__m128i *)v34;
  v10 = _mm_shuffle_epi32(_mm_cvtsi32_si128(4u), 0);
  v11 = _mm_shuffle_epi32(_mm_cvtsi32_si128(8u), 0);
  v12 = _mm_shuffle_epi32(_mm_cvtsi32_si128(0xCu), 0);
  v13 = _mm_shuffle_epi32(_mm_cvtsi32_si128(0x10u), 0);
  do
  {
    ++v9;
    v14 = _mm_add_epi32(v4, v10);
    v15 = _mm_unpackhi_epi16(v4, v14);
    v16 = _mm_add_epi32(v4, v12);
    v17 = _mm_unpacklo_epi16(v4, v14);
    v18 = _mm_unpacklo_epi16(v17, v15);
    v19 = _mm_unpackhi_epi16(v17, v15);
    v20 = v4;
    v4 = _mm_add_epi32(v4, v13);
    v21 = _mm_unpacklo_epi16(v18, v19);
    v22 = _mm_add_epi32(v20, v11);
    v23 = _mm_unpacklo_epi16(v22, v16);
    v24 = _mm_unpackhi_epi16(v22, v16);
    v9[-1] = _mm_packus_epi16(
               _mm_and_si128(v21, v5),
               _mm_and_si128(_mm_unpacklo_epi16(_mm_unpacklo_epi16(v23, v24), _mm_unpackhi_epi16(v23, v24)), v5));
  }
  while ( v9 != (__m128i *)&v35 );
  v25 = 0;
  LOBYTE(v26) = 0;
  do
  {
    v27 = v25;
    v28 = *v8;
    ++v25;
    ++v8;
    v26 = (unsigned __int8)(v26 + v28 + *(_BYTE *)(a1 + v27 % a2));
    result = v26;
    *(v8 - 1) = v34[v26];
    v34[v26] = v28;
  }
  while ( v25 != 256 );
  if ( a4 != 0 )
  {
    v30 = &a3[a4];
    LOBYTE(v31) = 0;
    LOBYTE(v32) = 0;
    do
    {
      v32 = (unsigned __int8)(v32 + 1);
      v33 = v34[v32];
      v31 = (unsigned __int8)(v33 + v31);
      v34[v32] = v34[v31];
      v34[v31] = v33;
      result = (unsigned __int8)v34[(unsigned __int8)(v34[v32] + v33)];
      *a3++ ^= result;
    }
    while ( v30 != a3 );
  }
  return result;
}
