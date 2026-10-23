__int64 __fastcall sha512_hash(void *src, size_t n, __int64 a3)
{
  size_t v4; // r12
  size_t v5; // rbp
  char *v7; // rax
  int v8; // ecx
  char *v9; // r8
  char *v10; // rbp
  size_t v11; // rax
  unsigned __int64 v12; // rcx
  unsigned __int64 v13; // r13
  _BYTE *v14; // rsi
  unsigned __int8 *v15; // rdx
  unsigned __int8 *v16; // rdi
  __int64 v17; // rax
  __int64 v18; // r8
  _BYTE *v19; // r10
  __m128i v20; // xmm0
  __m128i *v21; // rax
  __m128i v22; // xmm2
  __int64 v23; // rdx
  __int64 v24; // r11
  _QWORD *v25; // rdi
  __m128i v26; // rcx
  unsigned __int64 v27; // rbp
  __int64 v28; // r8
  __int64 v29; // r9
  __int64 i; // rsi
  __int64 v31; // rax
  __int64 v32; // r14
  __int64 v33; // rax
  __m128i *p_si128; // r8
  __int64 j; // rdi
  unsigned __int64 v36; // rsi
  __int64 result; // rax
  int k; // ecx
  unsigned __int64 v39; // rdx
  unsigned __int64 v40; // [rsp+0h] [rbp-4D8h]
  __m128i v41; // [rsp+8h] [rbp-4D0h]
  __int64 v42; // [rsp+18h] [rbp-4C0h]
  __m128i v43; // [rsp+20h] [rbp-4B8h]
  __m128i v44; // [rsp+30h] [rbp-4A8h]
  unsigned __int64 v45; // [rsp+40h] [rbp-498h]
  char *v46; // [rsp+50h] [rbp-488h]
  __int64 v47; // [rsp+58h] [rbp-480h]
  __m128i si128; // [rsp+60h] [rbp-478h] BYREF
  __m128i v49; // [rsp+70h] [rbp-468h]
  __m128i v50; // [rsp+80h] [rbp-458h]
  __m128i v51; // [rsp+90h] [rbp-448h]
  _BYTE dest[384]; // [rsp+A0h] [rbp-438h] BYREF
  _BYTE v53[112]; // [rsp+220h] [rbp-2B8h] BYREF
  __m128i v54; // [rsp+290h] [rbp-248h] BYREF
  char v55; // [rsp+2A0h] [rbp-238h] BYREF
  char v56; // [rsp+4A0h] [rbp-38h] BYREF

  v4 = 8 * n;
  v5 = (n + 16) >> 7;
  v45 = (v5 + 1) << 7;
  memset(dest, 0, sizeof(dest));
  si128 = _mm_load_si128((const __m128i *)&xmmword_6F00);
  v49 = _mm_load_si128((const __m128i *)&xmmword_6F10);
  v50 = _mm_load_si128((const __m128i *)&xmmword_6F20);
  v51 = _mm_load_si128((const __m128i *)&xmmword_6F30);
  v7 = (char *)memcpy(dest, src, n);
  v8 = 0;
  dest[n] = 0x80;
  v9 = v7;
  v10 = &v7[128 * v5];
  do
  {
    --v10;
    v11 = v4 >> v8;
    v8 += 8;
    v10[128] = v11;
  }
  while ( v8 != 64 );
  if ( v45 != 0 )
  {
    v47 = a3;
    v12 = 0;
    v44.m128i_i64[1] = 0x5BE0CD19137E2179LL;
    v44.m128i_i64[0] = 0x1F83D9ABFB41BD6BLL;
    v43.m128i_i64[1] = 0x9B05688C2B3E6C1FLL;
    v43.m128i_i64[0] = 0x510E527FADE682D1LL;
    v40 = 0xA54FF53A5F1D36F1LL;
    v42 = 0x3C6EF372FE94F82BLL;
    v41.m128i_i64[1] = 0xBB67AE8584CAA73BLL;
    v41.m128i_i64[0] = 0x6A09E667F3BCC908LL;
    v46 = v9 + 8;
    while ( 1 )
    {
      v13 = v12 + 128;
      v14 = &v53[-v12];
      v15 = (unsigned __int8 *)&v46[v12];
      do
      {
        v16 = v15 - 8;
        v17 = 0;
        do
        {
          v18 = *v16++;
          v17 = v18 | (v17 << 8);
        }
        while ( v15 != v16 );
        *(_QWORD *)&v14[v12] = v17;
        v12 += 8LL;
        v19 = v53;
        v15 += 8;
      }
      while ( v12 != v13 );
      v20 = _mm_load_si128(&v54);
      v21 = (__m128i *)&v55;
      do
      {
        v22 = _mm_loadu_si128((__m128i *)((char *)++v21 - 136));
        v20 = _mm_add_epi64(
                _mm_add_epi64(_mm_loadu_si128((__m128i *)((char *)v21 - 72)), v21[-9]),
                _mm_add_epi64(
                  _mm_xor_si128(
                    _mm_xor_si128(
                      _mm_or_si128(_mm_slli_epi64(v20, 3u), _mm_srli_epi64(v20, 0x3Du)),
                      _mm_or_si128(_mm_slli_epi64(v20, 0x2Du), _mm_srli_epi64(v20, 0x13u))),
                    _mm_srli_epi64(v20, 6u)),
                  _mm_xor_si128(
                    _mm_xor_si128(
                      _mm_or_si128(_mm_slli_epi64(v22, 0x38u), _mm_srli_epi64(v22, 8u)),
                      _mm_or_si128(_mm_slli_epi64(v22, 0x3Fu), _mm_srli_epi64(v22, 1u))),
                    _mm_srli_epi64(v22, 7u))));
        v21[-1] = v20;
      }
      while ( v21 != (__m128i *)&v56 );
      v23 = v44.m128i_i64[1];
      v24 = v44.m128i_i64[0];
      v25 = &SHA512_K;
      v26 = v43;
      v27 = v40;
      v28 = v42;
      v29 = v41.m128i_i64[1];
      for ( i = v41.m128i_i64[0]; ; i = v33 )
      {
        ++v25;
        v19 += 8;
        v31 = v23
            + (v26.m128i_i64[1] & v26.m128i_i64[0] ^ v24 & ~v26.m128i_i64[0])
            + *(v25 - 1)
            + *((_QWORD *)v19 - 1)
            + (__ROL8__(v26.m128i_i64[0], 23) ^ __ROR8__(v26.m128i_i64[0], 18) ^ __ROR8__(v26.m128i_i64[0], 14));
        v32 = v31 + v27;
        v27 = v28;
        v33 = (v28 & v29 ^ i & (v28 ^ v29)) + (__ROL8__(i, 25) ^ __ROL8__(i, 30) ^ __ROR8__(i, 28)) + v31;
        v23 = v24;
        if ( v25 == (_QWORD *)&SHA256_K )
          break;
        v24 = v26.m128i_i64[1];
        v28 = v29;
        v26.m128i_i64[1] = v26.m128i_i64[0];
        v29 = i;
        v26.m128i_i64[0] = v32;
      }
      v41.m128i_i64[0] += v33;
      v41.m128i_i64[1] += i;
      v42 += v29;
      v40 += v28;
      v43.m128i_i64[0] += v32;
      v43.m128i_i64[1] += v26.m128i_i64[0];
      v44.m128i_i64[0] += v26.m128i_i64[1];
      v44.m128i_i64[1] += v24;
      if ( v13 >= v45 )
        break;
      v12 = v13;
    }
    a3 = v47;
    si128 = v41;
    v49.m128i_i64[0] = v42;
    v49.m128i_i64[1] = v40;
    v50 = v43;
    v51 = v44;
  }
  p_si128 = &si128;
  for ( j = 0; j != 64; j += 8 )
  {
    v36 = p_si128->m128i_i64[0];
    result = a3 + j;
    for ( k = 56; k != -8; k -= 8 )
    {
      ++result;
      v39 = v36 >> k;
      *(_BYTE *)(result - 1) = v39;
    }
    p_si128 = (__m128i *)((char *)p_si128 + 8);
  }
  return result;
}
