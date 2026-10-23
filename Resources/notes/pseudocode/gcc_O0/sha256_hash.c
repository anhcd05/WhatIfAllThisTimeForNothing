_BYTE *__fastcall sha256_hash(const void *a1, size_t a2, __int64 a3)
{
  _BYTE *result; // rax
  _DWORD v7[64]; // [rsp+20h] [rbp-2D0h]
  int v8; // [rsp+120h] [rbp-1D0h]
  int v9; // [rsp+124h] [rbp-1CCh]
  int v10; // [rsp+128h] [rbp-1C8h]
  int v11; // [rsp+12Ch] [rbp-1C4h]
  int v12; // [rsp+130h] [rbp-1C0h]
  int v13; // [rsp+134h] [rbp-1BCh]
  int v14; // [rsp+138h] [rbp-1B8h]
  int v15; // [rsp+13Ch] [rbp-1B4h]
  _BYTE s[320]; // [rsp+140h] [rbp-1B0h] BYREF
  int v17; // [rsp+280h] [rbp-70h]
  int v18; // [rsp+284h] [rbp-6Ch]
  int v19; // [rsp+288h] [rbp-68h]
  int v20; // [rsp+28Ch] [rbp-64h]
  int v21; // [rsp+290h] [rbp-60h]
  int v22; // [rsp+294h] [rbp-5Ch]
  int v23; // [rsp+298h] [rbp-58h]
  int v24; // [rsp+29Ch] [rbp-54h]
  size_t v25; // [rsp+2A0h] [rbp-50h]
  size_t v26; // [rsp+2A8h] [rbp-48h]
  int kk; // [rsp+2B0h] [rbp-40h]
  int jj; // [rsp+2B4h] [rbp-3Ch]
  int v29; // [rsp+2B8h] [rbp-38h]
  int v30; // [rsp+2BCh] [rbp-34h]
  int v31; // [rsp+2C0h] [rbp-30h]
  int v32; // [rsp+2C4h] [rbp-2Ch]
  int v33; // [rsp+2C8h] [rbp-28h]
  int v34; // [rsp+2CCh] [rbp-24h]
  int v35; // [rsp+2D0h] [rbp-20h]
  int v36; // [rsp+2D4h] [rbp-1Ch]
  int ii; // [rsp+2D8h] [rbp-18h]
  int m; // [rsp+2DCh] [rbp-14h]
  _BYTE *k; // [rsp+2E0h] [rbp-10h]
  int j; // [rsp+2E8h] [rbp-8h]
  int i; // [rsp+2ECh] [rbp-4h]

  v26 = (((a2 + 8) >> 6) + 1) << 6;
  v25 = 8 * a2;
  for ( i = 0; i <= 7; ++i )
    *(&v8 + i) = SHA256_H0[i];
  memset(s, c: 0, n: sizeof(s));
  memcpy(dest: s, src: a1, n: a2);
  s[a2] = 0x80;
  for ( j = 0; j <= 7; ++j )
    s[v26 - j - 1] = v25 >> (8 * (unsigned __int8)j);
  for ( k = nullptr; ; k += 64 )
  {
    result = k;
    if ( (unsigned __int64)k >= v26 )
      break;
    for ( m = 0; m <= 15; ++m )
      v7[m] = (unsigned __int8)s[(_QWORD)&k[4 * m + 3]]
            | ((unsigned __int8)s[(_QWORD)&k[4 * m + 2]] << 8)
            | ((unsigned __int8)s[(_QWORD)&k[4 * m + 1]] << 16)
            | ((unsigned __int8)s[(_QWORD)&k[4 * m]] << 24);
    for ( ii = 16; ii <= 63; ++ii )
    {
      v18 = __ROL4__(v7[ii - 15], 14) ^ __ROR4__(v7[ii - 15], 7) ^ (v7[ii - 15] >> 3);
      v17 = __ROL4__(v7[ii - 2], 13) ^ __ROL4__(v7[ii - 2], 15) ^ (v7[ii - 2] >> 10);
      v7[ii] = v17 + v7[ii - 7] + v18 + v7[ii - 16];
    }
    v36 = v8;
    v35 = v9;
    v34 = v10;
    v33 = v11;
    v32 = v12;
    v31 = v13;
    v30 = v14;
    v29 = v15;
    for ( jj = 0; jj <= 63; ++jj )
    {
      v24 = __ROR4__(v32, 11) ^ __ROR4__(v32, 6) ^ __ROL4__(v32, 7);
      v23 = v31 & v32 ^ v30 & ~v32;
      v22 = v24 + v29 + v23 + SHA256_K[jj] + v7[jj];
      v21 = __ROR4__(v36, 13) ^ __ROR4__(v36, 2) ^ __ROL4__(v36, 10);
      v20 = v36 & (v34 ^ v35) ^ v34 & v35;
      v19 = v21 + v20;
      v29 = v30;
      v30 = v31;
      v31 = v32;
      v32 = v33 + v22;
      v33 = v34;
      v34 = v35;
      v35 = v36;
      v36 = v22 + v21 + v20;
    }
    v8 += v36;
    v9 += v35;
    v10 += v34;
    v11 += v33;
    v12 += v32;
    v13 += v31;
    v14 += v30;
    v15 += v29;
  }
  for ( kk = 0; kk <= 7; ++kk )
  {
    *(_BYTE *)(4 * kk + a3) = HIBYTE(*(&v8 + kk));
    *(_BYTE *)(4 * kk + 1LL + a3) = BYTE2(*(&v8 + kk));
    *(_BYTE *)(4 * kk + 2LL + a3) = BYTE1(*(&v8 + kk));
    result = (_BYTE *)(4 * kk + 3LL + a3);
    *result = *(&v8 + kk);
  }
  return result;
}
