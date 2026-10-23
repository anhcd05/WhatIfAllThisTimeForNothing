size_t __fastcall sha256_hash(void *src, size_t n, _QWORD *a3)
{
  size_t v4; // r12
  size_t v5; // rbp
  const __m128i *v7; // rax
  int v8; // ecx
  const __m128i *v9; // r10
  const __m128i *v10; // r15
  const __m128i *v11; // rbp
  size_t result; // rax
  __m128i v13; // xmm3
  __m128i v14; // xmm1
  __m128i v15; // xmm9
  __m128i v16; // xmm0
  __m128i v17; // xmm7
  _QWORD *v18; // r11
  const __m128i *v19; // rax
  __m128i v20; // xmm5
  __m128i v21; // xmm10
  __m128i v22; // xmm0
  __m128i v23; // xmm11
  __m128i v24; // xmm7
  __m128i v25; // xmm6
  __m128i v26; // xmm5
  __m128i v27; // xmm8
  __m128i v28; // xmm6
  __m128i v29; // xmm9
  __m128i v30; // xmm1
  __m128i v31; // xmm10
  __m128i v32; // xmm7
  __m128i v33; // xmm10
  __m128i v34; // xmm11
  __m128i v35; // xmm0
  __m128i v36; // xmm12
  __m128i v37; // xmm5
  int v38; // edx
  _DWORD *v39; // r8
  int v40; // ebx
  int v41; // ebp
  int v42; // ecx
  __int32 v43; // r12d
  __int32 v44; // edi
  __int32 v45; // r9d
  __int32 i; // esi
  int v47; // eax
  int v48; // r14d
  __int32 v49; // eax
  __m128i v50; // xmm0
  __m128i v51; // xmm7
  __m128i v52; // xmm2
  __m128i v53; // xmm5
  __m128i v54; // xmm4
  __m128i v55; // xmm1
  __m128i v56; // xmm6
  __m128i v57; // xmm9
  __m128i v58; // xmm8
  __m128i v59; // xmm3
  __m128i v60; // xmm6
  __m128i v61; // xmm1
  __m128i v62; // xmm8
  __m128i v63; // xmm0
  __m128i v64; // xmm2
  __m128i v65; // xmm2
  __m128i v66; // xmm1
  unsigned __int64 v67; // [rsp+0h] [rbp-2D8h]
  int v68; // [rsp+8h] [rbp-2D0h]
  __m128i v69; // [rsp+Ch] [rbp-2CCh]
  int v70; // [rsp+1Ch] [rbp-2BCh]
  __int64 v71; // [rsp+20h] [rbp-2B8h]
  unsigned __int64 v72; // [rsp+30h] [rbp-2A8h]
  _QWORD *v73; // [rsp+38h] [rbp-2A0h]
  __m128i si128; // [rsp+40h] [rbp-298h] BYREF
  __m128i v75; // [rsp+50h] [rbp-288h] BYREF
  _QWORD v76[6]; // [rsp+60h] [rbp-278h] BYREF
  __m128i v77; // [rsp+90h] [rbp-248h]
  char v78; // [rsp+A0h] [rbp-238h] BYREF
  _BYTE dest[376]; // [rsp+160h] [rbp-178h] BYREF

  v4 = 8 * n;
  v5 = (n + 8) >> 6;
  v72 = (v5 + 1) << 6;
  memset(dest, 0, 0x140u);
  si128 = _mm_load_si128((const __m128i *)&xmmword_6EE0);
  v75 = _mm_load_si128((const __m128i *)&xmmword_6EF0);
  v7 = (const __m128i *)memcpy(dest, src, n);
  v8 = 0;
  dest[n] = 0x80;
  v9 = v7;
  v10 = v7;
  v11 = &v7[4 * v5];
  do
  {
    v11 = (const __m128i *)((char *)v11 - 1);
    result = v4 >> v8;
    v8 += 8;
    v11[4].m128i_i8[0] = result;
  }
  while ( v8 != 64 );
  if ( v72 != 0 )
  {
    v71 = 0x5BE0CD191F83D9ABLL;
    v13 = _mm_srli_epi16((__m128i)-1LL, 8u);
    v68 = -1694144372;
    v70 = 1359893119;
    v69.m128i_i64[1] = 0xA54FF53A3C6EF372LL;
    v69.m128i_i64[0] = 0xBB67AE856A09E667LL;
    v67 = 0;
    v73 = a3;
    do
    {
      v14 = _mm_load_si128(v10);
      v15 = _mm_load_si128(v10 + 1);
      v16 = _mm_load_si128(v10 + 2);
      v17 = _mm_load_si128(v10 + 3);
      v18 = v76;
      v19 = (const __m128i *)&v78;
      v20 = _mm_packus_epi16(_mm_and_si128(v13, v14), _mm_and_si128(v13, v15));
      v21 = _mm_packus_epi16(_mm_and_si128(v13, v16), _mm_and_si128(v13, v17));
      v22 = _mm_packus_epi16(_mm_srli_epi16(v16, 8u), _mm_srli_epi16(v17, 8u));
      v23 = _mm_packus_epi16(_mm_srli_epi16(v20, 8u), _mm_srli_epi16(v21, 8u));
      v24 = _mm_packus_epi16(_mm_srli_epi16(v14, 8u), _mm_srli_epi16(v15, 8u));
      v25 = _mm_packus_epi16(_mm_and_si128(v20, v13), _mm_and_si128(v21, v13));
      v26 = _mm_unpackhi_epi8(v25, (__m128i)0LL);
      v27 = _mm_slli_epi16(_mm_unpackhi_epi8(v23, (__m128i)0LL), 8u);
      v28 = _mm_unpacklo_epi8(v25, (__m128i)0LL);
      v29 = _mm_packus_epi16(_mm_and_si128(v24, v13), _mm_and_si128(v22, v13));
      v30 = _mm_unpackhi_epi8(v29, (__m128i)0LL);
      v31 = _mm_packus_epi16(_mm_srli_epi16(v24, 8u), _mm_srli_epi16(v22, 8u));
      v32 = _mm_unpackhi_epi8(v31, (__m128i)0LL);
      v33 = _mm_unpacklo_epi8(v31, (__m128i)0LL);
      v34 = _mm_slli_epi16(_mm_unpacklo_epi8(v23, (__m128i)0LL), 8u);
      v77 = _mm_or_si128(
              _mm_or_si128(
                _mm_slli_epi32(_mm_unpackhi_epi16(v26, (__m128i)0LL), 0x18u),
                _mm_unpackhi_epi16(v27, (__m128i)0LL)),
              _mm_or_si128(
                _mm_slli_epi32(_mm_unpackhi_epi16(v30, (__m128i)0LL), 0x10u),
                _mm_unpackhi_epi16(v32, (__m128i)0LL)));
      v35 = _mm_srli_si128(v77, 8);
      v36 = _mm_unpacklo_epi8(v29, (__m128i)0LL);
      *(__m128i *)v76 = _mm_or_si128(
                          _mm_or_si128(
                            _mm_slli_epi32(_mm_unpacklo_epi16(v36, (__m128i)0LL), 0x10u),
                            _mm_unpacklo_epi16(v33, (__m128i)0LL)),
                          _mm_or_si128(
                            _mm_unpacklo_epi16(v34, (__m128i)0LL),
                            _mm_slli_epi32(_mm_unpacklo_epi16(v28, (__m128i)0LL), 0x18u)));
      *(__m128i *)&v76[2] = _mm_or_si128(
                              _mm_or_si128(
                                _mm_slli_epi32(_mm_unpackhi_epi16(v28, (__m128i)0LL), 0x18u),
                                _mm_unpackhi_epi16(v34, (__m128i)0LL)),
                              _mm_or_si128(
                                _mm_slli_epi32(_mm_unpackhi_epi16(v36, (__m128i)0LL), 0x10u),
                                _mm_unpackhi_epi16(v33, (__m128i)0LL)));
      *(__m128i *)&v76[4] = _mm_or_si128(
                              _mm_or_si128(
                                _mm_slli_epi32(_mm_unpacklo_epi16(v30, (__m128i)0LL), 0x10u),
                                _mm_unpacklo_epi16(v32, (__m128i)0LL)),
                              _mm_or_si128(
                                _mm_slli_epi32(_mm_unpacklo_epi16(v26, (__m128i)0LL), 0x18u),
                                _mm_unpacklo_epi16(v27, (__m128i)0LL)));
      do
      {
        v19 = (const __m128i *)((char *)v19 + 8);
        v37 = _mm_loadl_epi64((const __m128i *)((char *)v19 - 68));
        v35 = _mm_add_epi32(
                _mm_add_epi32(
                  _mm_loadl_epi64((const __m128i *)((char *)v19 - 36)),
                  _mm_loadl_epi64((const __m128i *)((char *)v19 - 72))),
                _mm_add_epi32(
                  _mm_xor_si128(
                    _mm_xor_si128(
                      _mm_or_si128(_mm_slli_epi32(v35, 0xDu), _mm_srli_epi32(v35, 0x13u)),
                      _mm_or_si128(_mm_slli_epi32(v35, 0xFu), _mm_srli_epi32(v35, 0x11u))),
                    _mm_srli_epi32(v35, 0xAu)),
                  _mm_xor_si128(
                    _mm_xor_si128(
                      _mm_or_si128(_mm_slli_epi32(v37, 0xEu), _mm_srli_epi32(v37, 0x12u)),
                      _mm_or_si128(_mm_slli_epi32(v37, 0x19u), _mm_srli_epi32(v37, 7u))),
                    _mm_srli_epi32(v37, 3u))));
        v19[-1].m128i_i64[1] = v35.m128i_i64[0];
      }
      while ( v9 != v19 );
      v38 = HIDWORD(v71);
      v39 = &SHA256_K;
      v40 = v71;
      v41 = v68;
      v42 = v70;
      v43 = v69.m128i_i32[3];
      v44 = v69.m128i_i32[2];
      v45 = v69.m128i_i32[1];
      for ( i = v69.m128i_i32[0]; ; i = v49 )
      {
        ++v39;
        v18 = (_QWORD *)((char *)v18 + 4);
        v47 = v38
            + (v42 & v41 ^ v40 & ~v42)
            + *(v39 - 1)
            + *((_DWORD *)v18 - 1)
            + (__ROL4__(v42, 7) ^ __ROR4__(v42, 11) ^ __ROR4__(v42, 6));
        v48 = v47 + v43;
        v43 = v44;
        v49 = (v45 & v44 ^ i & (v45 ^ v44)) + (__ROL4__(i, 10) ^ __ROR4__(i, 13) ^ __ROR4__(i, 2)) + v47;
        v38 = v40;
        if ( v39 == MD5_K )
          break;
        v40 = v41;
        v44 = v45;
        v41 = v42;
        v45 = i;
        v42 = v48;
      }
      HIDWORD(v71) += v40;
      v69.m128i_i32[0] += v49;
      v69.m128i_i32[1] += i;
      v10 += 4;
      v69.m128i_i32[2] += v45;
      v69.m128i_i32[3] += v44;
      v70 += v48;
      v68 += v42;
      LODWORD(v71) = v41 + v71;
      v67 += 64LL;
    }
    while ( v67 < v72 );
    a3 = v73;
    si128 = v69;
    v75.m128i_i64[0] = __PAIR64__(v68, v70);
    v75.m128i_i64[1] = v71;
    result = HIDWORD(v71);
  }
  v50 = _mm_loadl_epi64(&si128);
  v51 = _mm_loadl_epi64((const __m128i *)&si128.m128i_u64[1]);
  v52 = _mm_loadl_epi64(&v75);
  v53 = _mm_loadl_epi64((const __m128i *)&v75.m128i_u64[1]);
  v54 = _mm_loadl_epi64((const __m128i *)&qword_6F60);
  v55 = _mm_unpacklo_epi16(_mm_unpacklo_epi16(v50, v51), _mm_shuffle_epi32(_mm_unpacklo_epi16(v50, v51), 78));
  v56 = _mm_unpacklo_epi16(_mm_unpacklo_epi16(v52, v53), _mm_shuffle_epi32(_mm_unpacklo_epi16(v52, v53), 78));
  v57 = _mm_unpacklo_epi8(
          _mm_shuffle_epi32(
            _mm_packus_epi16(_mm_and_si128(_mm_srli_epi16(v55, 8u), v54), _mm_and_si128(_mm_srli_epi16(v56, 8u), v54)),
            8),
          _mm_shuffle_epi32(_mm_packus_epi16(_mm_and_si128(v54, v55), _mm_and_si128(v54, v56)), 8));
  v58 = _mm_unpacklo_epi16(_mm_srli_epi32(v50, 0x10u), _mm_srli_epi32(v51, 0x10u));
  v59 = _mm_shuffle_epi32(v57, 78);
  v60 = _mm_srli_epi32(v52, 0x10u);
  v61 = _mm_unpacklo_epi16(v58, _mm_shuffle_epi32(v58, 78));
  v62 = _mm_srli_epi32(v53, 0x10u);
  v63 = _mm_unpacklo_epi16(_mm_srli_epi32(v50, 0x18u), _mm_srli_epi32(v51, 0x18u));
  v64 = _mm_unpacklo_epi16(_mm_srli_epi32(v52, 0x18u), _mm_srli_epi32(v53, 0x18u));
  v65 = _mm_unpacklo_epi8(
          _mm_shuffle_epi32(
            _mm_packus_epi16(
              _mm_and_si128(_mm_unpacklo_epi16(v63, _mm_shuffle_epi32(v63, 78)), v54),
              _mm_and_si128(v54, _mm_unpacklo_epi16(v64, _mm_shuffle_epi32(v64, 78)))),
            8),
          _mm_shuffle_epi32(
            _mm_packus_epi16(
              _mm_and_si128(v61, v54),
              _mm_and_si128(
                _mm_unpacklo_epi16(_mm_unpacklo_epi16(v60, v62), _mm_shuffle_epi32(_mm_unpacklo_epi16(v60, v62), 78)),
                v54)),
            8));
  *a3 = _mm_unpacklo_epi16(v65, v57).m128i_u64[0];
  v66 = _mm_shuffle_epi32(v65, 78);
  a3[1] = _mm_shuffle_epi32(_mm_unpacklo_epi16(v65, v57), 78).m128i_u64[0];
  a3[2] = _mm_unpacklo_epi16(v66, v59).m128i_u64[0];
  a3[3] = _mm_shuffle_epi32(_mm_unpacklo_epi16(v66, v59), 78).m128i_u64[0];
  return result;
}
