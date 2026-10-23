// md5_hash = sub_40C0 (bản strip, IDA không có tên hàm)
__m128i *__fastcall sub_40C0(void *src, size_t n, __m128i *a3)
{
  const __m128i *v4; // rbx
  size_t v5; // r15
  unsigned int v6; // r14d
  unsigned int v7; // ebp
  unsigned int v8; // r12d
  unsigned int v9; // r13d
  unsigned int v10; // r9d
  unsigned int v11; // r8d
  unsigned int v12; // edi
  unsigned int v13; // eax
  unsigned __int64 v14; // rsi
  __int64 v15; // rcx
  int v16; // edx
  int v17; // edx
  int v18; // ecx
  unsigned int v19; // edx
  int v20; // ecx
  unsigned int v21; // edx
  size_t v23; // [rsp+0h] [rbp-1C8h]
  _QWORD v25[6]; // [rsp+10h] [rbp-1B8h]
  __m128i si128; // [rsp+40h] [rbp-188h]
  _BYTE dest[376]; // [rsp+50h] [rbp-178h] BYREF

  v4 = (const __m128i *)dest;
  v23 = ((n + 8) & 0xFFFFFFFFFFFFFFC0LL) + 64;
  memset(dest, 0, 0x140u);
  memcpy(dest, src, n);
  dest[n] = 0x80;
  *(__int64 *)((char *)&si128.m128i_i64[1] + v23) = 8 * n;
  if ( v23 == 0 )
  {
    v6 = 271733878;
    v8 = -1732584194;
    v9 = -271733879;
    v7 = 1732584193;
    goto LABEL_14;
  }
  v5 = 0;
  v6 = 271733878;
  v7 = 1732584193;
  v8 = -1732584194;
  v9 = -271733879;
  do
  {
    v10 = v6;
    v11 = v8;
    v12 = v9;
    v13 = v7;
    v14 = 0;
    *(__m128i *)v25 = _mm_load_si128(v4);
    *(__m128i *)&v25[2] = _mm_load_si128(v4 + 1);
    *(__m128i *)&v25[4] = _mm_load_si128(v4 + 2);
    si128 = _mm_load_si128(v4 + 3);
    while ( 1 )
    {
      if ( v14 <= 0xF )
      {
        v15 = (unsigned int)v14;
        v16 = v10 ^ v12 & (v10 ^ v11);
        goto LABEL_6;
      }
      if ( v14 <= 0x1F )
      {
        v15 = (5 * (_BYTE)v14 + 1) & 0xF;
        v16 = v11 ^ v10 & (v11 ^ v12);
        goto LABEL_6;
      }
      if ( v14 <= 0x2F )
      {
        v15 = (3 * (_BYTE)v14 + 5) & 0xF;
        v16 = v10 ^ v11 ^ v12;
LABEL_6:
        v17 = *((_DWORD *)v25 + v15) + dword_67C0[v14] + v16;
        v18 = dword_61E0[v14++];
        v19 = v12 + __ROL4__(v13 + v17, v18);
        goto LABEL_7;
      }
      v20 = dword_61E0[v14];
      v21 = v13 + *((_DWORD *)v25 + ((7 * (_BYTE)v14) & 0xF)) + dword_67C0[v14] + (v11 ^ (v12 | ~v10));
      ++v14;
      v19 = v12 + __ROL4__(v21, v20);
      if ( v14 == 64 )
        break;
LABEL_7:
      v13 = v10;
      v10 = v11;
      v11 = v12;
      v12 = v19;
    }
    v7 += v10;
    v9 += v19;
    v8 += v12;
    v6 += v11;
    v5 += 64LL;
    v4 += 4;
  }
  while ( v5 < v23 );
LABEL_14:
  *a3 = _mm_unpacklo_epi64(
          _mm_unpacklo_epi32(_mm_cvtsi32_si128(v7), _mm_cvtsi32_si128(v9)),
          _mm_unpacklo_epi32(_mm_cvtsi32_si128(v8), _mm_cvtsi32_si128(v6)));
  return a3;
}
