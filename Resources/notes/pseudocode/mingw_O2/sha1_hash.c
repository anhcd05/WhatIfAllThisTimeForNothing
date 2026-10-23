__int64 __fastcall sha1_hash(void *Src, size_t Size, __int64 a3)
{
  const __m128i *v3; // rsi
  size_t v5; // rbp
  size_t v7; // rax
  size_t v8; // r12
  _BYTE *v9; // rbp
  int i; // ecx
  size_t v11; // rax
  __int32 v12; // r15d
  int v13; // ebp
  int v14; // r12d
  int v15; // r13d
  int v16; // r14d
  __m128i *v17; // rdi
  __int64 v18; // r8
  __m128i v19; // xmm5
  __m128i v20; // xmm10
  __int128 *v21; // rax
  __m128i v22; // xmm8
  __m128i v23; // xmm2
  __m128i v24; // xmm0
  __m128i v25; // xmm1
  __m128i v26; // xmm7
  __m128i v27; // xmm9
  __m128i v28; // xmm2
  __m128i v29; // xmm8
  __m128i v30; // xmm0
  __m128i v31; // xmm10
  __m128i v32; // xmm12
  __m128i v33; // xmm11
  __m128i v34; // xmm7
  __m128i v35; // xmm9
  __m128i v36; // xmm12
  __m128i v37; // xmm2
  __m128i v38; // xmm8
  __m128i v39; // xmm1
  __m128i v40; // xmm11
  __m128i v41; // xmm9
  __int64 v42; // rdx
  __m128i v43; // xmm3
  __m128i v44; // xmm0
  __m128i v45; // xmm2
  __int64 v46; // rcx
  __m128i v47; // xmm2
  __m128i v48; // xmm0
  __int32 v49; // ebx
  int v50; // r9d
  int v51; // r10d
  int v52; // ecx
  int v53; // r11d
  unsigned __int64 v54; // rdx
  int v55; // r14d
  int v56; // esi
  int v57; // ecx
  __int32 v58; // eax
  int v59; // eax
  __int32 v60; // esi
  int v61; // eax
  __int64 v62; // rdx
  unsigned int v63; // eax
  __int64 result; // rax
  size_t v65; // [rsp+20h] [rbp-368h]
  const __m128i *v66; // [rsp+28h] [rbp-360h]
  int v67; // [rsp+34h] [rbp-354h]
  size_t v68; // [rsp+38h] [rbp-350h]
  _BYTE v69[320]; // [rsp+40h] [rbp-348h] BYREF
  __m128i v70; // [rsp+180h] [rbp-208h] BYREF
  __m128i v71; // [rsp+190h] [rbp-1F8h]
  __m128i v72; // [rsp+1A0h] [rbp-1E8h]
  __m128i v73; // [rsp+1B0h] [rbp-1D8h]
  char v74; // [rsp+1C0h] [rbp-1C8h] BYREF
  __int128 v75; // [rsp+2C0h] [rbp-C8h] BYREF

  v3 = (const __m128i *)v69;
  v5 = (Size + 8) >> 6;
  v7 = v5 + 1;
  v8 = 8 * Size;
  v9 = &v69[64 * v5];
  v68 = v7 << 6;
  memset(v69, 0, sizeof(v69));
  memcpy_0(a1: v69, Src, Size);
  v69[Size] = 0x80;
  for ( i = 0; i != 64; i += 8 )
  {
    --v9;
    v11 = v8 >> i;
    v9[64] = v11;
  }
  v12 = -1009589776;
  v13 = 271733878;
  v14 = -1732584194;
  v15 = -271733879;
  v16 = 1732584193;
  v17 = &v70;
  if ( v68 != 0 )
  {
    v18 = a3;
    v65 = 0;
    v19 = _mm_srli_epi16((__m128i)-1LL, 8u);
    while ( 1 )
    {
      v20 = _mm_loadu_si128(v3 + 1);
      v21 = (__int128 *)&v74;
      v22 = _mm_loadu_si128(v3 + 3);
      v23 = _mm_loadu_si128(v3);
      v24 = _mm_loadu_si128(v3 + 2);
      v25 = _mm_packus_epi16(_mm_and_si128(v23, v19), _mm_and_si128(v20, v19));
      v43 = _mm_packus_epi16(_mm_and_si128(v24, v19), _mm_and_si128(v22, v19));
      v26 = _mm_packus_epi16(_mm_srli_epi16(v23, 8u), _mm_srli_epi16(v20, 8u));
      v27 = _mm_packus_epi16(_mm_srli_epi16(v24, 8u), _mm_srli_epi16(v22, 8u));
      v28 = _mm_packus_epi16(_mm_and_si128(v26, v19), _mm_and_si128(v27, v19));
      v29 = _mm_packus_epi16(_mm_and_si128(v19, v25), _mm_and_si128(v19, v43));
      v30 = _mm_unpacklo_epi8(v28, (__m128i)0LL);
      v31 = _mm_unpacklo_epi8(v29, (__m128i)0LL);
      v32 = _mm_packus_epi16(_mm_srli_epi16(v25, 8u), _mm_srli_epi16(v43, 8u));
      v33 = _mm_unpackhi_epi8(v32, (__m128i)0LL);
      v34 = _mm_packus_epi16(_mm_srli_epi16(v26, 8u), _mm_srli_epi16(v27, 8u));
      v35 = _mm_unpacklo_epi8(v34, (__m128i)0LL);
      v36 = _mm_slli_epi16(_mm_unpacklo_epi8(v32, (__m128i)0LL), 8u);
      v37 = _mm_unpackhi_epi8(v28, (__m128i)0LL);
      v38 = _mm_unpackhi_epi8(v29, (__m128i)0LL);
      v70 = _mm_or_si128(
              _mm_or_si128(
                _mm_slli_epi32(_mm_unpacklo_epi16(v30, (__m128i)0LL), 0x10u),
                _mm_slli_epi32(_mm_unpacklo_epi16(v31, (__m128i)0LL), 0x18u)),
              _mm_or_si128(_mm_unpacklo_epi16(v35, (__m128i)0LL), _mm_unpacklo_epi16(v36, (__m128i)0LL)));
      v39 = _mm_srli_si128(v70, 8);
      v40 = _mm_slli_epi16(v33, 8u);
      v71 = _mm_or_si128(
              _mm_or_si128(
                _mm_slli_epi32(_mm_unpackhi_epi16(v30, (__m128i)0LL), 0x10u),
                _mm_slli_epi32(_mm_unpackhi_epi16(v31, (__m128i)0LL), 0x18u)),
              _mm_or_si128(_mm_unpackhi_epi16(v35, (__m128i)0LL), _mm_unpackhi_epi16(v36, (__m128i)0LL)));
      v41 = _mm_unpackhi_epi8(v34, (__m128i)0LL);
      v42 = v71.m128i_i64[0];
      v43.m128i_i64[0] = _mm_srli_si128(v71, 8).m128i_u64[0];
      v72 = _mm_or_si128(
              _mm_or_si128(
                _mm_slli_epi32(_mm_unpacklo_epi16(v37, (__m128i)0LL), 0x10u),
                _mm_slli_epi32(_mm_unpacklo_epi16(v38, (__m128i)0LL), 0x18u)),
              _mm_or_si128(_mm_unpacklo_epi16(v41, (__m128i)0LL), _mm_unpacklo_epi16(v40, (__m128i)0LL)));
      v73 = _mm_or_si128(
              _mm_or_si128(
                _mm_slli_epi32(_mm_unpackhi_epi16(v37, (__m128i)0LL), 0x10u),
                _mm_slli_epi32(_mm_unpackhi_epi16(v38, (__m128i)0LL), 0x18u)),
              _mm_or_si128(_mm_unpackhi_epi16(v41, (__m128i)0LL), _mm_unpackhi_epi16(v40, (__m128i)0LL)));
      do
      {
        v44 = _mm_loadl_epi64((const __m128i *)((char *)v21 - 12));
        v45 = _mm_loadl_epi64((const __m128i *)v21 - 4);
        v46 = v43.m128i_i64[0];
        v21 = (__int128 *)((char *)v21 + 8);
        v43 = _mm_loadl_epi64((const __m128i *)((char *)v21 - 40));
        v47 = _mm_xor_si128(v45, v39);
        v39 = (__m128i)(unsigned __int64)v42;
        v42 = v46;
        v48 = _mm_xor_si128(v47, _mm_xor_si128(v44, v43));
        *((_QWORD *)v21 - 1) = _mm_or_si128(_mm_slli_epi32(v48, 1u), _mm_srli_epi32(v48, 0x1Fu)).m128i_u64[0];
      }
      while ( v21 != &v75 );
      v66 = v3;
      v49 = v12;
      v50 = v13;
      v51 = v14;
      v67 = v16;
      v52 = v15;
      v53 = v16;
      v54 = 0;
      while ( 1 )
      {
        if ( v54 <= 0x13 )
        {
          v55 = 1518500249;
          v56 = v50 ^ v52 & (v51 ^ v50);
          goto LABEL_9;
        }
        if ( v54 <= 0x27 )
        {
          v55 = 1859775393;
          v56 = v52 ^ v51 ^ v50;
LABEL_9:
          v57 = __ROR4__(v52, 2);
          v58 = v70.m128i_i32[v54++] + __ROL4__(v53, 5);
          v59 = v49 + v56 + v55 + v58;
          goto LABEL_10;
        }
        if ( v54 <= 0x3B )
        {
          v55 = -1894007588;
          v56 = v51 & v50 | v52 & (v51 | v50);
          goto LABEL_9;
        }
        v60 = v70.m128i_i32[v54++] + __ROL4__(v53, 5);
        v61 = v52 ^ v51 ^ v50;
        v57 = __ROR4__(v52, 2);
        v59 = v49 + v60 + v61 - 899497514;
        if ( v54 == 80 )
          break;
LABEL_10:
        v49 = v50;
        v50 = v51;
        v51 = v57;
        v52 = v53;
        v53 = v59;
      }
      v15 += v53;
      v14 += v57;
      v65 += 64LL;
      v13 += v51;
      v12 += v50;
      v16 = v59 + v67;
      v3 = v66 + 4;
      if ( v65 >= v68 )
      {
        a3 = v18;
        break;
      }
    }
  }
  v70.m128i_i64[0] = __PAIR64__(v15, v16);
  v62 = a3 + 20;
  v70.m128i_i64[1] = __PAIR64__(v13, v14);
  v71.m128i_i32[0] = v12;
  do
  {
    v63 = v17->m128i_i32[0];
    a3 += 4;
    v17 = (__m128i *)((char *)v17 + 4);
    result = _byteswap_ulong(v63);
    *(_DWORD *)(a3 - 4) = result;
  }
  while ( v62 != a3 );
  return result;
}
