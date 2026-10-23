__int64 __fastcall sha1_hash(void *src, size_t n, __int64 a3)
{
  size_t v4; // rbp
  size_t v5; // rbx
  const __m128i *v6; // rax
  int v7; // ecx
  const __m128i *v8; // r11
  const __m128i *v9; // rbx
  size_t v10; // rax
  __int32 v11; // r15d
  int v12; // ebp
  int v13; // r12d
  int v14; // r13d
  int v15; // r14d
  __m128i *v16; // rbx
  __int64 v17; // rsi
  __m128i v18; // xmm5
  __m128i si128; // xmm10
  const __m128i *v20; // rax
  __m128i v21; // xmm8
  __m128i v22; // xmm2
  __m128i v23; // xmm0
  __m128i v24; // xmm1
  __m128i v25; // xmm7
  __m128i v26; // xmm9
  __m128i v27; // xmm2
  __m128i v28; // xmm8
  __m128i v29; // xmm0
  __m128i v30; // xmm10
  __m128i v31; // xmm12
  __m128i v32; // xmm11
  __m128i v33; // xmm7
  __m128i v34; // xmm9
  __m128i v35; // xmm12
  __m128i v36; // xmm2
  __m128i v37; // xmm8
  __m128i v38; // xmm1
  __m128i v39; // xmm11
  __m128i v40; // xmm9
  __int64 v41; // rdx
  __m128i v42; // xmm3
  __m128i v43; // xmm0
  __m128i v44; // xmm2
  __int64 v45; // rcx
  __m128i v46; // xmm2
  __m128i v47; // xmm0
  __int32 v48; // r10d
  int v49; // edi
  int v50; // r8d
  int v51; // ecx
  int v52; // r9d
  unsigned __int64 v53; // rdx
  int v54; // r11d
  int v55; // esi
  int v56; // ecx
  __int32 v57; // eax
  int v58; // eax
  __int32 v59; // esi
  int v60; // eax
  __int64 result; // rax
  unsigned int v62; // edx
  unsigned __int64 v63; // [rsp+0h] [rbp-2D8h]
  __int64 v64; // [rsp+8h] [rbp-2D0h]
  const __m128i *v65; // [rsp+8h] [rbp-2D0h]
  unsigned __int64 v66; // [rsp+10h] [rbp-2C8h]
  _BYTE dest[320]; // [rsp+20h] [rbp-2B8h] BYREF
  __m128i v69; // [rsp+160h] [rbp-178h] BYREF
  __m128i v70; // [rsp+170h] [rbp-168h]
  __m128i v71; // [rsp+180h] [rbp-158h]
  __m128i v72; // [rsp+190h] [rbp-148h]
  char v73; // [rsp+1A0h] [rbp-138h] BYREF
  char v74; // [rsp+2A0h] [rbp-38h] BYREF

  v4 = 8 * n;
  v5 = (n + 8) >> 6;
  v64 = (v5 + 1) << 6;
  memset(dest, 0, sizeof(dest));
  v6 = (const __m128i *)memcpy(dest, src, n);
  dest[n] = 0x80;
  v7 = 0;
  v8 = v6;
  v9 = &v6[4 * v5];
  do
  {
    v9 = (const __m128i *)((char *)v9 - 1);
    v10 = v4 >> v7;
    v7 += 8;
    v9[4].m128i_i8[0] = v10;
  }
  while ( v7 != 64 );
  v11 = -1009589776;
  v12 = 271733878;
  v13 = -1732584194;
  v14 = -271733879;
  v15 = 1732584193;
  v16 = &v69;
  if ( v64 != 0 )
  {
    v63 = 0;
    v17 = v64;
    v18 = _mm_srli_epi16((__m128i)-1LL, 8u);
    do
    {
      si128 = _mm_load_si128(v8 + 1);
      v20 = (const __m128i *)&v73;
      v21 = _mm_load_si128(v8 + 3);
      v22 = _mm_load_si128(v8);
      v23 = _mm_load_si128(v8 + 2);
      v24 = _mm_packus_epi16(_mm_and_si128(v22, v18), _mm_and_si128(si128, v18));
      v42 = _mm_packus_epi16(_mm_and_si128(v23, v18), _mm_and_si128(v21, v18));
      v25 = _mm_packus_epi16(_mm_srli_epi16(v22, 8u), _mm_srli_epi16(si128, 8u));
      v26 = _mm_packus_epi16(_mm_srli_epi16(v23, 8u), _mm_srli_epi16(v21, 8u));
      v27 = _mm_packus_epi16(_mm_and_si128(v25, v18), _mm_and_si128(v26, v18));
      v28 = _mm_packus_epi16(_mm_and_si128(v18, v24), _mm_and_si128(v18, v42));
      v29 = _mm_unpacklo_epi8(v27, (__m128i)0LL);
      v30 = _mm_unpacklo_epi8(v28, (__m128i)0LL);
      v31 = _mm_packus_epi16(_mm_srli_epi16(v24, 8u), _mm_srli_epi16(v42, 8u));
      v32 = _mm_unpackhi_epi8(v31, (__m128i)0LL);
      v33 = _mm_packus_epi16(_mm_srli_epi16(v25, 8u), _mm_srli_epi16(v26, 8u));
      v34 = _mm_unpacklo_epi8(v33, (__m128i)0LL);
      v35 = _mm_slli_epi16(_mm_unpacklo_epi8(v31, (__m128i)0LL), 8u);
      v36 = _mm_unpackhi_epi8(v27, (__m128i)0LL);
      v37 = _mm_unpackhi_epi8(v28, (__m128i)0LL);
      v69 = _mm_or_si128(
              _mm_or_si128(
                _mm_slli_epi32(_mm_unpacklo_epi16(v29, (__m128i)0LL), 0x10u),
                _mm_slli_epi32(_mm_unpacklo_epi16(v30, (__m128i)0LL), 0x18u)),
              _mm_or_si128(_mm_unpacklo_epi16(v34, (__m128i)0LL), _mm_unpacklo_epi16(v35, (__m128i)0LL)));
      v38 = _mm_srli_si128(v69, 8);
      v39 = _mm_slli_epi16(v32, 8u);
      v70 = _mm_or_si128(
              _mm_or_si128(
                _mm_slli_epi32(_mm_unpackhi_epi16(v29, (__m128i)0LL), 0x10u),
                _mm_slli_epi32(_mm_unpackhi_epi16(v30, (__m128i)0LL), 0x18u)),
              _mm_or_si128(_mm_unpackhi_epi16(v34, (__m128i)0LL), _mm_unpackhi_epi16(v35, (__m128i)0LL)));
      v40 = _mm_unpackhi_epi8(v33, (__m128i)0LL);
      v41 = v70.m128i_i64[0];
      v42.m128i_i64[0] = _mm_srli_si128(v70, 8).m128i_u64[0];
      v71 = _mm_or_si128(
              _mm_or_si128(
                _mm_slli_epi32(_mm_unpacklo_epi16(v36, (__m128i)0LL), 0x10u),
                _mm_slli_epi32(_mm_unpacklo_epi16(v37, (__m128i)0LL), 0x18u)),
              _mm_or_si128(_mm_unpacklo_epi16(v40, (__m128i)0LL), _mm_unpacklo_epi16(v39, (__m128i)0LL)));
      v72 = _mm_or_si128(
              _mm_or_si128(
                _mm_slli_epi32(_mm_unpackhi_epi16(v36, (__m128i)0LL), 0x10u),
                _mm_slli_epi32(_mm_unpackhi_epi16(v37, (__m128i)0LL), 0x18u)),
              _mm_or_si128(_mm_unpackhi_epi16(v40, (__m128i)0LL), _mm_unpackhi_epi16(v39, (__m128i)0LL)));
      do
      {
        v43 = _mm_loadl_epi64((const __m128i *)((char *)v20 - 12));
        v44 = _mm_loadl_epi64(v20 - 4);
        v45 = v42.m128i_i64[0];
        v20 = (const __m128i *)((char *)v20 + 8);
        v42 = _mm_loadl_epi64((const __m128i *)((char *)v20 - 40));
        v46 = _mm_xor_si128(v44, v38);
        v38 = (__m128i)(unsigned __int64)v41;
        v41 = v45;
        v47 = _mm_xor_si128(v46, _mm_xor_si128(v43, v42));
        v20[-1].m128i_i64[1] = _mm_or_si128(_mm_slli_epi32(v47, 1u), _mm_srli_epi32(v47, 0x1Fu)).m128i_u64[0];
      }
      while ( v20 != (const __m128i *)&v74 );
      v65 = v8;
      v48 = v11;
      v49 = v12;
      v50 = v13;
      v66 = v17;
      v51 = v14;
      v52 = v15;
      v53 = 0;
      while ( 1 )
      {
        if ( v53 <= 0x13 )
        {
          v54 = 1518500249;
          v55 = v49 ^ v51 & (v50 ^ v49);
          goto LABEL_9;
        }
        if ( v53 <= 0x27 )
        {
          v54 = 1859775393;
          v55 = v51 ^ v50 ^ v49;
LABEL_9:
          v56 = __ROR4__(v51, 2);
          v57 = v69.m128i_i32[v53++] + __ROL4__(v52, 5);
          v58 = v48 + v55 + v54 + v57;
          goto LABEL_10;
        }
        if ( v53 <= 0x3B )
        {
          v54 = -1894007588;
          v55 = v50 & v49 | v51 & (v50 | v49);
          goto LABEL_9;
        }
        v59 = v69.m128i_i32[v53++] + __ROL4__(v52, 5);
        v60 = v51 ^ v50 ^ v49;
        v56 = __ROR4__(v51, 2);
        v58 = v48 + v59 + v60 - 899497514;
        if ( v53 == 80 )
          break;
LABEL_10:
        v48 = v49;
        v49 = v50;
        v50 = v56;
        v51 = v52;
        v52 = v58;
      }
      v63 += 64LL;
      v15 += v58;
      v14 += v52;
      v17 = v66;
      v13 += v56;
      v12 += v50;
      v11 += v49;
      v8 = v65 + 4;
    }
    while ( v63 < v66 );
  }
  result = a3;
  v69.m128i_i64[0] = __PAIR64__(v14, v15);
  v69.m128i_i64[1] = __PAIR64__(v12, v13);
  v70.m128i_i32[0] = v11;
  do
  {
    v62 = v16->m128i_i32[0];
    result += 4;
    v16 = (__m128i *)((char *)v16 + 4);
    *(_DWORD *)(result - 4) = _byteswap_ulong(v62);
  }
  while ( a3 + 20 != result );
  return result;
}
