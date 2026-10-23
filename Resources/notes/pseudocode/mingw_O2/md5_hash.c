unsigned __int64 __fastcall md5_hash(void *Src, size_t Size, __m128i *a3)
{
  unsigned __int64 result; // rax
  __m128i *v5; // r9
  const __m128i *v6; // rdi
  size_t v7; // r15
  unsigned int v8; // r14d
  unsigned int v9; // r12d
  unsigned int v10; // r13d
  unsigned int v11; // ebp
  __m128i v12; // xmm3
  unsigned int v13; // r11d
  unsigned int v14; // r10d
  __m128i v15; // xmm4
  __m128i v16; // xmm5
  unsigned int v17; // r9d
  unsigned __int64 v18; // r8
  __int64 v19; // rcx
  int v20; // edx
  int v21; // edx
  int v22; // ecx
  unsigned int v23; // edx
  int v24; // ecx
  int v25; // edx
  size_t v26; // [rsp+28h] [rbp-1D0h]
  _QWORD v27[6]; // [rsp+30h] [rbp-1C8h]
  __m128i v28; // [rsp+60h] [rbp-198h]
  _BYTE v29[392]; // [rsp+70h] [rbp-188h] BYREF

  memset(v29, 0, 0x140u);
  v26 = ((Size + 8) & 0xFFFFFFFFFFFFFFC0uLL) + 64;
  result = (unsigned __int64)memcpy_0(a1: v29, Src, Size);
  v29[Size] = 0x80;
  *(_QWORD *)((char *)&v28 + ((Size + 8) & 0xFFFFFFFFFFFFFFC0uLL) + 72) = 8 * Size;
  v5 = a3;
  if ( ((Size + 8) & 0xFFFFFFFFFFFFFFC0uLL) == 0xFFFFFFFFFFFFFFC0uLL )
  {
    v8 = 271733878;
    v9 = -1732584194;
    v10 = -271733879;
    v11 = 1732584193;
    goto LABEL_15;
  }
  v6 = (const __m128i *)result;
  v7 = 0;
  v8 = 271733878;
  v9 = -1732584194;
  v10 = -271733879;
  v11 = 1732584193;
  do
  {
    v12 = _mm_loadu_si128(v6 + 1);
    v13 = v8;
    v14 = v9;
    v15 = _mm_loadu_si128(v6 + 2);
    v16 = _mm_loadu_si128(v6 + 3);
    v17 = v10;
    result = v11;
    *(__m128i *)v27 = _mm_loadu_si128(v6);
    v18 = 0;
    *(__m128i *)&v27[2] = v12;
    *(__m128i *)&v27[4] = v15;
    v28 = v16;
    while ( 1 )
    {
      if ( v18 <= 0xF )
      {
        v19 = (unsigned int)v18;
        v20 = v13 ^ v17 & (v13 ^ v14);
        goto LABEL_6;
      }
      if ( v18 <= 0x1F )
      {
        v19 = (5 * (_BYTE)v18 + 1) & 0xF;
        v20 = v14 ^ v13 & (v14 ^ v17);
        goto LABEL_6;
      }
      if ( v18 <= 0x2F )
      {
        v19 = (3 * (_BYTE)v18 + 5) & 0xF;
        v20 = v13 ^ v14 ^ v17;
LABEL_6:
        v21 = *((_DWORD *)v27 + v19) + MD5_K[v18] + v20;
        v22 = R_1[v18++];
        v23 = v17 + __ROL4__(result + v21, v22);
        goto LABEL_7;
      }
      v24 = R_1[v18];
      v25 = result + *((_DWORD *)v27 + ((7 * (_BYTE)v18) & 0xF)) + MD5_K[v18] + (v14 ^ (v17 | ~v13));
      ++v18;
      v23 = v17 + __ROL4__(v25, v24);
      if ( v18 == 64 )
        break;
LABEL_7:
      result = v13;
      v13 = v14;
      v14 = v17;
      v17 = v23;
    }
    v11 += v13;
    v10 += v23;
    v9 += v17;
    v8 += v14;
    v7 += 64LL;
    v6 += 4;
  }
  while ( v7 < v26 );
  v5 = a3;
LABEL_15:
  *v5 = _mm_unpacklo_epi64(
          _mm_unpacklo_epi32(_mm_cvtsi32_si128(v11), _mm_cvtsi32_si128(v10)),
          _mm_unpacklo_epi32(_mm_cvtsi32_si128(v9), _mm_cvtsi32_si128(v8)));
  return result;
}
