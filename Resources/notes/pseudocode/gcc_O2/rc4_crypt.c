__int64 __fastcall rc4_crypt(__int64 a1, unsigned __int64 a2, _BYTE *a3, __int64 a4)
{
  _BYTE *v7; // r11
  __m128i si128; // xmm2
  char *v9; // rsi
  __m128i v10; // xmm5
  __m128i v11; // xmm7
  __m128i v12; // xmm9
  __m128i *v13; // rax
  __m128i v14; // xmm8
  __m128i v15; // xmm6
  __m128i v16; // xmm3
  __m128i v17; // xmm0
  __m128i v18; // xmm4
  __m128i v19; // xmm3
  __m128i v20; // xmm1
  __m128i v21; // xmm3
  __m128i v22; // xmm0
  __m128i v23; // xmm1
  __m128i v24; // xmm3
  __m128i v25; // xmm0
  __m128i v26; // xmm3
  unsigned __int64 v27; // rcx
  unsigned int v28; // r9d
  unsigned __int64 v29; // rax
  char v30; // di
  __int64 result; // rax
  _BYTE *v32; // rbx
  int v33; // edi
  int v34; // esi
  char v35; // al
  _BYTE v36[256]; // [rsp+0h] [rbp-108h] BYREF
  char v37; // [rsp+100h] [rbp-8h] BYREF

  v7 = a3;
  si128 = _mm_load_si128((const __m128i *)&xmmword_6EC0);
  v9 = v36;
  v10 = _mm_srli_epi16((__m128i)-1LL, 8u);
  v11 = _mm_shuffle_epi32(_mm_cvtsi32_si128(0xCu), 0);
  v12 = _mm_shuffle_epi32(_mm_cvtsi32_si128(4u), 0);
  v13 = (__m128i *)v36;
  v14 = _mm_shuffle_epi32(_mm_cvtsi32_si128(8u), 0);
  v15 = _mm_shuffle_epi32(_mm_cvtsi32_si128(0x10u), 0);
  do
  {
    ++v13;
    v16 = _mm_add_epi32(si128, v12);
    v17 = _mm_unpackhi_epi16(si128, v16);
    v18 = _mm_add_epi32(si128, v11);
    v19 = _mm_unpacklo_epi16(si128, v16);
    v20 = _mm_unpacklo_epi16(v19, v17);
    v21 = _mm_unpackhi_epi16(v19, v17);
    v22 = si128;
    si128 = _mm_add_epi32(si128, v15);
    v23 = _mm_unpacklo_epi16(v20, v21);
    v24 = _mm_add_epi32(v22, v14);
    v25 = _mm_unpacklo_epi16(v24, v18);
    v26 = _mm_unpackhi_epi16(v24, v18);
    v13[-1] = _mm_packus_epi16(
                _mm_and_si128(v23, v10),
                _mm_and_si128(_mm_unpacklo_epi16(_mm_unpacklo_epi16(v25, v26), _mm_unpackhi_epi16(v25, v26)), v10));
  }
  while ( v13 != (__m128i *)&v37 );
  v27 = 0;
  LOBYTE(v28) = 0;
  do
  {
    v29 = v27;
    v30 = *v9;
    ++v27;
    ++v9;
    v28 = (unsigned __int8)(v28 + v30 + *(_BYTE *)(a1 + v29 % a2));
    result = v28;
    *(v9 - 1) = v36[v28];
    v36[v28] = v30;
  }
  while ( v27 != 256 );
  if ( a4 != 0 )
  {
    v32 = &a3[a4];
    LOBYTE(v33) = 0;
    LOBYTE(v34) = 0;
    do
    {
      v34 = (unsigned __int8)(v34 + 1);
      v35 = v36[v34];
      v33 = (unsigned __int8)(v35 + v33);
      v36[v34] = v36[v33];
      v36[v33] = v35;
      result = (unsigned __int8)v36[(unsigned __int8)(v36[v34] + v35)];
      *v7++ ^= result;
    }
    while ( v32 != v7 );
  }
  return result;
}
