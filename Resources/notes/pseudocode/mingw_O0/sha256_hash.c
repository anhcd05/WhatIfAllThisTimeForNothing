_BYTE *__fastcall sha256_hash(const void *a1, size_t a2, __int64 a3)
{
  _BYTE *result; // rax
  _DWORD v4[64]; // [rsp+20h] [rbp-60h]
  int v5; // [rsp+120h] [rbp+A0h]
  int v6; // [rsp+124h] [rbp+A4h]
  int v7; // [rsp+128h] [rbp+A8h]
  int v8; // [rsp+12Ch] [rbp+ACh]
  int v9; // [rsp+130h] [rbp+B0h]
  int v10; // [rsp+134h] [rbp+B4h]
  int v11; // [rsp+138h] [rbp+B8h]
  int v12; // [rsp+13Ch] [rbp+BCh]
  _BYTE v13[320]; // [rsp+140h] [rbp+C0h] BYREF
  int v14; // [rsp+280h] [rbp+200h]
  int v15; // [rsp+284h] [rbp+204h]
  int v16; // [rsp+288h] [rbp+208h]
  int v17; // [rsp+28Ch] [rbp+20Ch]
  int v18; // [rsp+290h] [rbp+210h]
  int v19; // [rsp+294h] [rbp+214h]
  int v20; // [rsp+298h] [rbp+218h]
  int v21; // [rsp+29Ch] [rbp+21Ch]
  size_t v22; // [rsp+2A0h] [rbp+220h]
  size_t v23; // [rsp+2A8h] [rbp+228h]
  int jj; // [rsp+2B0h] [rbp+230h]
  int ii; // [rsp+2B4h] [rbp+234h]
  int v26; // [rsp+2B8h] [rbp+238h]
  int v27; // [rsp+2BCh] [rbp+23Ch]
  int v28; // [rsp+2C0h] [rbp+240h]
  int v29; // [rsp+2C4h] [rbp+244h]
  int v30; // [rsp+2C8h] [rbp+248h]
  int v31; // [rsp+2CCh] [rbp+24Ch]
  int v32; // [rsp+2D0h] [rbp+250h]
  int v33; // [rsp+2D4h] [rbp+254h]
  int n; // [rsp+2D8h] [rbp+258h]
  int m; // [rsp+2DCh] [rbp+25Ch]
  _BYTE *k; // [rsp+2E0h] [rbp+260h]
  int j; // [rsp+2E8h] [rbp+268h]
  int i; // [rsp+2ECh] [rbp+26Ch]

  v23 = (((a2 + 8) >> 6) + 1) << 6;
  v22 = 8 * a2;
  for ( i = 0; i <= 7; ++i )
    *(&v5 + i) = SHA256_H0[i];
  memset(a1: v13, Val: 0, Size: sizeof(v13));
  memcpy_0(a1: v13, Src: a1, Size: a2);
  v13[a2] = 0x80;
  for ( j = 0; j <= 7; ++j )
    v13[v23 - j - 1] = v22 >> (8 * (unsigned __int8)j);
  for ( k = nullptr; ; k += 64 )
  {
    result = k;
    if ( (unsigned __int64)k >= v23 )
      break;
    for ( m = 0; m <= 15; ++m )
      v4[m] = (unsigned __int8)v13[(_QWORD)&k[4 * m + 3]]
            | ((unsigned __int8)v13[(_QWORD)&k[4 * m + 2]] << 8)
            | ((unsigned __int8)v13[(_QWORD)&k[4 * m + 1]] << 16)
            | ((unsigned __int8)v13[(_QWORD)&k[4 * m]] << 24);
    for ( n = 16; n <= 63; ++n )
    {
      v15 = __ROL4__(v4[n - 15], 14) ^ __ROR4__(v4[n - 15], 7) ^ (v4[n - 15] >> 3);
      v14 = __ROL4__(v4[n - 2], 13) ^ __ROL4__(v4[n - 2], 15) ^ (v4[n - 2] >> 10);
      v4[n] = v14 + v4[n - 7] + v15 + v4[n - 16];
    }
    v33 = v5;
    v32 = v6;
    v31 = v7;
    v30 = v8;
    v29 = v9;
    v28 = v10;
    v27 = v11;
    v26 = v12;
    for ( ii = 0; ii <= 63; ++ii )
    {
      v21 = __ROR4__(v29, 11) ^ __ROR4__(v29, 6) ^ __ROL4__(v29, 7);
      v20 = v28 & v29 ^ v27 & ~v29;
      v19 = v21 + v26 + v20 + SHA256_K[ii] + v4[ii];
      v18 = __ROR4__(v33, 13) ^ __ROR4__(v33, 2) ^ __ROL4__(v33, 10);
      v17 = v33 & (v31 ^ v32) ^ v31 & v32;
      v16 = v18 + v17;
      v26 = v27;
      v27 = v28;
      v28 = v29;
      v29 = v30 + v19;
      v30 = v31;
      v31 = v32;
      v32 = v33;
      v33 = v19 + v18 + v17;
    }
    v5 += v33;
    v6 += v32;
    v7 += v31;
    v8 += v30;
    v9 += v29;
    v10 += v28;
    v11 += v27;
    v12 += v26;
  }
  for ( jj = 0; jj <= 7; ++jj )
  {
    *(_BYTE *)(4 * jj + a3) = HIBYTE(*(&v5 + jj));
    *(_BYTE *)(4 * jj + 1LL + a3) = BYTE2(*(&v5 + jj));
    *(_BYTE *)(4 * jj + 2LL + a3) = BYTE1(*(&v5 + jj));
    result = (_BYTE *)(4 * jj + 3LL + a3);
    *result = *(&v5 + jj);
  }
  return result;
}
