__int64 __fastcall sha512_hash(void *Src, size_t Size, __int64 a3)
{
  size_t v4; // rsi
  size_t v6; // rbp
  char *v7; // rax
  int v8; // ecx
  char *v9; // r9
  char *v10; // rsi
  size_t v11; // rax
  unsigned __int64 v12; // rcx
  unsigned __int64 v13; // r13
  _BYTE *v14; // r8
  unsigned __int8 *v15; // rdx
  unsigned __int8 *v16; // r9
  __int64 v17; // rax
  __int64 v18; // r10
  _BYTE *v19; // rbx
  __m128i v20; // xmm0
  __m128i *v21; // rax
  __m128i v22; // xmm2
  __int64 v23; // rdx
  __int64 v24; // rsi
  _QWORD *v25; // r9
  __int64 v26; // rdi
  __int64 v27; // rcx
  unsigned __int64 v28; // rbp
  __int64 v29; // r10
  __int64 v30; // r11
  __int64 i; // r8
  __int64 v32; // rax
  __int64 v33; // r14
  __int64 v34; // rax
  __m128i *v35; // r10
  __int64 j; // r9
  unsigned __int64 v37; // r8
  __int64 result; // rax
  int k; // ecx
  unsigned __int64 v40; // rdx
  unsigned __int64 v41; // [rsp+28h] [rbp-4E0h]
  __m128i v42; // [rsp+30h] [rbp-4D8h]
  __int64 v43; // [rsp+40h] [rbp-4C8h]
  __m128i v44; // [rsp+48h] [rbp-4C0h]
  __m128i v45; // [rsp+58h] [rbp-4B0h]
  unsigned __int64 v46; // [rsp+68h] [rbp-4A0h]
  char *v47; // [rsp+78h] [rbp-490h]
  __m128i v48; // [rsp+80h] [rbp-488h] BYREF
  __m128i v49; // [rsp+90h] [rbp-478h]
  __m128i v50; // [rsp+A0h] [rbp-468h]
  __m128i v51; // [rsp+B0h] [rbp-458h]
  _BYTE v52[384]; // [rsp+C0h] [rbp-448h] BYREF
  _BYTE v53[112]; // [rsp+240h] [rbp-2C8h] BYREF
  __m128i v54; // [rsp+2B0h] [rbp-258h] BYREF
  char v55; // [rsp+2C0h] [rbp-248h] BYREF
  char v56; // [rsp+4C0h] [rbp-48h] BYREF
  __int64 v57; // [rsp+520h] [rbp+18h]

  v48 = _mm_loadu_si128((const __m128i *)&xmmword_14000FF30);
  v4 = (Size + 16) >> 7;
  v49 = _mm_loadu_si128((const __m128i *)&xmmword_14000FF40);
  v6 = 8 * Size;
  v46 = (v4 + 1) << 7;
  memset(v52, 0, sizeof(v52));
  v50 = _mm_loadu_si128((const __m128i *)&xmmword_14000FF50);
  v51 = _mm_loadu_si128((const __m128i *)&xmmword_14000FF60);
  v7 = (char *)memcpy_0(a1: v52, Src, Size);
  v8 = 0;
  v52[Size] = 0x80;
  v9 = v7;
  v10 = &v7[128 * v4];
  do
  {
    --v10;
    v11 = v6 >> v8;
    v8 += 8;
    v10[128] = v11;
  }
  while ( v8 != 64 );
  if ( v46 != 0 )
  {
    v12 = 0;
    v57 = a3;
    v45.m128i_i64[1] = 0x5BE0CD19137E2179LL;
    v45.m128i_i64[0] = 0x1F83D9ABFB41BD6BLL;
    v44.m128i_i64[1] = 0x9B05688C2B3E6C1FuLL;
    v44.m128i_i64[0] = 0x510E527FADE682D1LL;
    v41 = 0xA54FF53A5F1D36F1uLL;
    v43 = 0x3C6EF372FE94F82BLL;
    v42.m128i_i64[1] = 0xBB67AE8584CAA73BuLL;
    v42.m128i_i64[0] = 0x6A09E667F3BCC908LL;
    v47 = v9 + 8;
    while ( 1 )
    {
      v13 = v12 + 128;
      v14 = &v53[-v12];
      v15 = (unsigned __int8 *)&v47[v12];
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
      v20 = _mm_loadu_si128(&v54);
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
      v23 = v45.m128i_i64[1];
      v24 = v45.m128i_i64[0];
      v25 = &SHA512_K;
      v26 = v44.m128i_i64[1];
      v27 = v44.m128i_i64[0];
      v28 = v41;
      v29 = v43;
      v30 = v42.m128i_i64[1];
      for ( i = v42.m128i_i64[0]; ; i = v34 )
      {
        ++v25;
        v19 += 8;
        v32 = v23
            + (v26 & v27 ^ v24 & ~v27)
            + *(v25 - 1)
            + *((_QWORD *)v19 - 1)
            + (__ROL8__(v27, 23) ^ __ROR8__(v27, 18) ^ __ROR8__(v27, 14));
        v33 = v32 + v28;
        v28 = v29;
        v34 = (v29 & v30 ^ i & (v29 ^ v30)) + (__ROL8__(i, 25) ^ __ROL8__(i, 30) ^ __ROR8__(i, 28)) + v32;
        v23 = v24;
        if ( v25 == (_QWORD *)&SHA256_K )
          break;
        v24 = v26;
        v29 = v30;
        v26 = v27;
        v30 = i;
        v27 = v33;
      }
      v42.m128i_i64[0] += v34;
      v42.m128i_i64[1] += i;
      v43 += v30;
      v41 += v29;
      v44.m128i_i64[0] += v33;
      v44.m128i_i64[1] += v27;
      v45.m128i_i64[0] += v26;
      v45.m128i_i64[1] += v24;
      if ( v13 >= v46 )
        break;
      v12 = v13;
    }
    a3 = v57;
    v48 = v42;
    v49.m128i_i64[0] = v43;
    v49.m128i_i64[1] = v41;
    v50 = v44;
    v51 = v45;
  }
  v35 = &v48;
  for ( j = 0; j != 64; j += 8 )
  {
    v37 = v35->m128i_i64[0];
    result = a3 + j;
    for ( k = 56; k != -8; k -= 8 )
    {
      ++result;
      v40 = v37 >> k;
      *(_BYTE *)(result - 1) = v40;
    }
    v35 = (__m128i *)((char *)v35 + 8);
  }
  return result;
}
