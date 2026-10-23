size_t __fastcall sha256_hash(void *Src, size_t Size, _QWORD *a3)
{
  size_t v4; // rbp
  size_t v6; // rax
  const __m128i *v7; // r15
  _BYTE *v8; // rbp
  size_t v9; // r12
  int v10; // ecx
  size_t result; // rax
  __m128i v12; // xmm3
  __m128i v13; // xmm1
  __m128i v14; // xmm9
  __m128i v15; // xmm0
  __m128i v16; // xmm7
  _QWORD *v17; // rsi
  char *v18; // rax
  __m128i v19; // xmm5
  __m128i v20; // xmm10
  __m128i v21; // xmm0
  __m128i v22; // xmm11
  __m128i v23; // xmm7
  __m128i v24; // xmm6
  __m128i v25; // xmm5
  __m128i v26; // xmm8
  __m128i v27; // xmm6
  __m128i v28; // xmm9
  __m128i v29; // xmm1
  __m128i v30; // xmm10
  __m128i v31; // xmm7
  __m128i v32; // xmm10
  __m128i v33; // xmm11
  __m128i v34; // xmm0
  __m128i v35; // xmm12
  __m128i v36; // xmm5
  int v37; // edx
  _DWORD *v38; // r10
  int v39; // edi
  int v40; // ebp
  int v41; // ecx
  __int32 v42; // r12d
  __int32 v43; // r9d
  __int32 v44; // r11d
  __int32 i; // r8d
  int v46; // eax
  int v47; // r14d
  __int32 v48; // eax
  __m128i v49; // xmm0
  __m128i v50; // xmm7
  __m128i v51; // xmm2
  __m128i v52; // xmm5
  __m128i v53; // xmm4
  __m128i v54; // xmm1
  __m128i v55; // xmm6
  __m128i v56; // xmm9
  __m128i v57; // xmm8
  __m128i v58; // xmm3
  __m128i v59; // xmm6
  __m128i v60; // xmm1
  __m128i v61; // xmm8
  __m128i v62; // xmm0
  __m128i v63; // xmm2
  __m128i v64; // xmm2
  __m128i v65; // xmm1
  size_t v66; // [rsp+28h] [rbp-370h]
  int v67; // [rsp+30h] [rbp-368h]
  __m128i v68; // [rsp+34h] [rbp-364h]
  int v69; // [rsp+44h] [rbp-354h]
  __int64 v70; // [rsp+48h] [rbp-350h]
  size_t v71; // [rsp+58h] [rbp-340h]
  __m128i v72; // [rsp+60h] [rbp-338h] BYREF
  __m128i v73; // [rsp+70h] [rbp-328h] BYREF
  _QWORD v74[6]; // [rsp+80h] [rbp-318h] BYREF
  __m128i v75; // [rsp+B0h] [rbp-2E8h]
  char v76; // [rsp+C0h] [rbp-2D8h] BYREF
  _BYTE v77[320]; // [rsp+180h] [rbp-218h] BYREF
  _QWORD *v78; // [rsp+3B0h] [rbp+18h]

  v72 = _mm_loadu_si128((const __m128i *)&xmmword_14000FF00);
  v4 = (Size + 8) >> 6;
  v6 = v4 + 1;
  v7 = (const __m128i *)v77;
  v8 = &v77[64 * v4];
  v71 = v6 << 6;
  v9 = 8 * Size;
  memset(v77, 0, sizeof(v77));
  v73 = _mm_loadu_si128((const __m128i *)&xmmword_14000FF10);
  memcpy_0(a1: v77, Src, Size);
  v10 = 0;
  v77[Size] = 0x80;
  do
  {
    --v8;
    result = v9 >> v10;
    v10 += 8;
    v8[64] = result;
  }
  while ( v10 != 64 );
  if ( v71 != 0 )
  {
    v70 = 0x5BE0CD191F83D9ABLL;
    v12 = _mm_srli_epi16((__m128i)-1LL, 8u);
    v67 = -1694144372;
    v69 = 1359893119;
    v68.m128i_i64[1] = 0xA54FF53A3C6EF372uLL;
    v68.m128i_i64[0] = 0xBB67AE856A09E667uLL;
    v66 = 0;
    v78 = a3;
    do
    {
      v13 = _mm_loadu_si128(v7);
      v14 = _mm_loadu_si128(v7 + 1);
      v15 = _mm_loadu_si128(v7 + 2);
      v16 = _mm_loadu_si128(v7 + 3);
      v17 = v74;
      v18 = &v76;
      v19 = _mm_packus_epi16(_mm_and_si128(v12, v13), _mm_and_si128(v12, v14));
      v20 = _mm_packus_epi16(_mm_and_si128(v12, v15), _mm_and_si128(v12, v16));
      v21 = _mm_packus_epi16(_mm_srli_epi16(v15, 8u), _mm_srli_epi16(v16, 8u));
      v22 = _mm_packus_epi16(_mm_srli_epi16(v19, 8u), _mm_srli_epi16(v20, 8u));
      v23 = _mm_packus_epi16(_mm_srli_epi16(v13, 8u), _mm_srli_epi16(v14, 8u));
      v24 = _mm_packus_epi16(_mm_and_si128(v19, v12), _mm_and_si128(v20, v12));
      v25 = _mm_unpackhi_epi8(v24, (__m128i)0LL);
      v26 = _mm_slli_epi16(_mm_unpackhi_epi8(v22, (__m128i)0LL), 8u);
      v27 = _mm_unpacklo_epi8(v24, (__m128i)0LL);
      v28 = _mm_packus_epi16(_mm_and_si128(v23, v12), _mm_and_si128(v21, v12));
      v29 = _mm_unpackhi_epi8(v28, (__m128i)0LL);
      v30 = _mm_packus_epi16(_mm_srli_epi16(v23, 8u), _mm_srli_epi16(v21, 8u));
      v31 = _mm_unpackhi_epi8(v30, (__m128i)0LL);
      v32 = _mm_unpacklo_epi8(v30, (__m128i)0LL);
      v33 = _mm_slli_epi16(_mm_unpacklo_epi8(v22, (__m128i)0LL), 8u);
      v75 = _mm_or_si128(
              _mm_or_si128(
                _mm_slli_epi32(_mm_unpackhi_epi16(v25, (__m128i)0LL), 0x18u),
                _mm_unpackhi_epi16(v26, (__m128i)0LL)),
              _mm_or_si128(
                _mm_slli_epi32(_mm_unpackhi_epi16(v29, (__m128i)0LL), 0x10u),
                _mm_unpackhi_epi16(v31, (__m128i)0LL)));
      v34 = _mm_srli_si128(v75, 8);
      v35 = _mm_unpacklo_epi8(v28, (__m128i)0LL);
      *(__m128i *)&v74[2] = _mm_or_si128(
                              _mm_or_si128(
                                _mm_slli_epi32(_mm_unpackhi_epi16(v27, (__m128i)0LL), 0x18u),
                                _mm_unpackhi_epi16(v33, (__m128i)0LL)),
                              _mm_or_si128(
                                _mm_slli_epi32(_mm_unpackhi_epi16(v35, (__m128i)0LL), 0x10u),
                                _mm_unpackhi_epi16(v32, (__m128i)0LL)));
      *(__m128i *)v74 = _mm_or_si128(
                          _mm_or_si128(
                            _mm_slli_epi32(_mm_unpacklo_epi16(v35, (__m128i)0LL), 0x10u),
                            _mm_unpacklo_epi16(v32, (__m128i)0LL)),
                          _mm_or_si128(
                            _mm_unpacklo_epi16(v33, (__m128i)0LL),
                            _mm_slli_epi32(_mm_unpacklo_epi16(v27, (__m128i)0LL), 0x18u)));
      *(__m128i *)&v74[4] = _mm_or_si128(
                              _mm_or_si128(
                                _mm_slli_epi32(_mm_unpacklo_epi16(v29, (__m128i)0LL), 0x10u),
                                _mm_unpacklo_epi16(v31, (__m128i)0LL)),
                              _mm_or_si128(
                                _mm_slli_epi32(_mm_unpacklo_epi16(v25, (__m128i)0LL), 0x18u),
                                _mm_unpacklo_epi16(v26, (__m128i)0LL)));
      do
      {
        v18 += 8;
        v36 = _mm_loadl_epi64((const __m128i *)(v18 - 68));
        v34 = _mm_add_epi32(
                _mm_add_epi32(
                  _mm_loadl_epi64((const __m128i *)(v18 - 36)),
                  _mm_loadl_epi64((const __m128i *)(v18 - 72))),
                _mm_add_epi32(
                  _mm_xor_si128(
                    _mm_xor_si128(
                      _mm_or_si128(_mm_slli_epi32(v34, 0xDu), _mm_srli_epi32(v34, 0x13u)),
                      _mm_or_si128(_mm_slli_epi32(v34, 0xFu), _mm_srli_epi32(v34, 0x11u))),
                    _mm_srli_epi32(v34, 0xAu)),
                  _mm_xor_si128(
                    _mm_xor_si128(
                      _mm_or_si128(_mm_slli_epi32(v36, 0xEu), _mm_srli_epi32(v36, 0x12u)),
                      _mm_or_si128(_mm_slli_epi32(v36, 0x19u), _mm_srli_epi32(v36, 7u))),
                    _mm_srli_epi32(v36, 3u))));
        *((_QWORD *)v18 - 1) = v34.m128i_i64[0];
      }
      while ( v77 != v18 );
      v37 = HIDWORD(v70);
      v38 = &SHA256_K;
      v39 = v70;
      v40 = v67;
      v41 = v69;
      v42 = v68.m128i_i32[3];
      v43 = v68.m128i_i32[2];
      v44 = v68.m128i_i32[1];
      for ( i = v68.m128i_i32[0]; ; i = v48 )
      {
        ++v38;
        v17 = (_QWORD *)((char *)v17 + 4);
        v46 = v37
            + (v41 & v40 ^ v39 & ~v41)
            + *(v38 - 1)
            + *((_DWORD *)v17 - 1)
            + (__ROL4__(v41, 7) ^ __ROR4__(v41, 11) ^ __ROR4__(v41, 6));
        v47 = v46 + v42;
        v42 = v43;
        v48 = (v44 & v43 ^ i & (v44 ^ v43)) + (__ROL4__(i, 10) ^ __ROR4__(i, 13) ^ __ROR4__(i, 2)) + v46;
        v37 = v39;
        if ( v38 == MD5_K )
          break;
        v39 = v40;
        v43 = v44;
        v40 = v41;
        v44 = i;
        v41 = v47;
      }
      v68.m128i_i32[0] += v48;
      v68.m128i_i32[1] += i;
      v68.m128i_i32[2] += v44;
      v7 += 4;
      v68.m128i_i32[3] += v43;
      v69 += v47;
      v67 += v41;
      LODWORD(v70) = v40 + v70;
      HIDWORD(v70) += v39;
      v66 += 64LL;
    }
    while ( v66 < v71 );
    a3 = v78;
    v72 = v68;
    v73.m128i_i64[0] = __PAIR64__(v67, v69);
    v73.m128i_i64[1] = v70;
    result = HIDWORD(v70);
  }
  v49 = _mm_loadl_epi64(&v72);
  v50 = _mm_loadl_epi64((const __m128i *)&v72.m128i_u64[1]);
  v51 = _mm_loadl_epi64(&v73);
  v52 = _mm_loadl_epi64((const __m128i *)&v73.m128i_u64[1]);
  v53 = _mm_loadl_epi64((const __m128i *)&qword_14000FF20);
  v54 = _mm_unpacklo_epi16(_mm_unpacklo_epi16(v49, v50), _mm_shuffle_epi32(_mm_unpacklo_epi16(v49, v50), 78));
  v55 = _mm_unpacklo_epi16(_mm_unpacklo_epi16(v51, v52), _mm_shuffle_epi32(_mm_unpacklo_epi16(v51, v52), 78));
  v56 = _mm_unpacklo_epi8(
          _mm_shuffle_epi32(
            _mm_packus_epi16(_mm_and_si128(_mm_srli_epi16(v54, 8u), v53), _mm_and_si128(_mm_srli_epi16(v55, 8u), v53)),
            8),
          _mm_shuffle_epi32(_mm_packus_epi16(_mm_and_si128(v53, v54), _mm_and_si128(v53, v55)), 8));
  v57 = _mm_unpacklo_epi16(_mm_srli_epi32(v49, 0x10u), _mm_srli_epi32(v50, 0x10u));
  v58 = _mm_shuffle_epi32(v56, 78);
  v59 = _mm_srli_epi32(v51, 0x10u);
  v60 = _mm_unpacklo_epi16(v57, _mm_shuffle_epi32(v57, 78));
  v61 = _mm_srli_epi32(v52, 0x10u);
  v62 = _mm_unpacklo_epi16(_mm_srli_epi32(v49, 0x18u), _mm_srli_epi32(v50, 0x18u));
  v63 = _mm_unpacklo_epi16(_mm_srli_epi32(v51, 0x18u), _mm_srli_epi32(v52, 0x18u));
  v64 = _mm_unpacklo_epi8(
          _mm_shuffle_epi32(
            _mm_packus_epi16(
              _mm_and_si128(_mm_unpacklo_epi16(v62, _mm_shuffle_epi32(v62, 78)), v53),
              _mm_and_si128(v53, _mm_unpacklo_epi16(v63, _mm_shuffle_epi32(v63, 78)))),
            8),
          _mm_shuffle_epi32(
            _mm_packus_epi16(
              _mm_and_si128(v60, v53),
              _mm_and_si128(
                _mm_unpacklo_epi16(_mm_unpacklo_epi16(v59, v61), _mm_shuffle_epi32(_mm_unpacklo_epi16(v59, v61), 78)),
                v53)),
            8));
  *a3 = _mm_unpacklo_epi16(v64, v56).m128i_u64[0];
  v65 = _mm_shuffle_epi32(v64, 78);
  a3[1] = _mm_shuffle_epi32(_mm_unpacklo_epi16(v64, v56), 78).m128i_u64[0];
  a3[2] = _mm_unpacklo_epi16(v65, v58).m128i_u64[0];
  a3[3] = _mm_shuffle_epi32(_mm_unpacklo_epi16(v65, v58), 78).m128i_u64[0];
  return result;
}
