unsigned __int64 __fastcall sha1_hash(const void *a1, size_t a2, __int64 a3)
{
  unsigned __int64 result; // rax
  _DWORD v7[80]; // [rsp+20h] [rbp-310h]
  _DWORD v8[8]; // [rsp+160h] [rbp-1D0h]
  _BYTE s[332]; // [rsp+180h] [rbp-1B0h] BYREF
  int v10; // [rsp+2CCh] [rbp-64h]
  size_t v11; // [rsp+2D0h] [rbp-60h]
  size_t v12; // [rsp+2D8h] [rbp-58h]
  int jj; // [rsp+2E4h] [rbp-4Ch]
  int v14; // [rsp+2E8h] [rbp-48h]
  int v15; // [rsp+2ECh] [rbp-44h]
  int ii; // [rsp+2F0h] [rbp-40h]
  _DWORD v17[3]; // [rsp+2F4h] [rbp-3Ch]
  int v18; // [rsp+300h] [rbp-30h]
  int v19; // [rsp+304h] [rbp-2Ch]
  int m; // [rsp+308h] [rbp-28h]
  int k; // [rsp+30Ch] [rbp-24h]
  size_t j; // [rsp+310h] [rbp-20h]
  int i; // [rsp+318h] [rbp-18h]
  __int64 v24; // [rsp+31Ch] [rbp-14h]
  int v25; // [rsp+324h] [rbp-Ch]
  int v26; // [rsp+328h] [rbp-8h]
  int v27; // [rsp+32Ch] [rbp-4h]

  v27 = 1732584193;
  v26 = -271733879;
  v25 = -1732584194;
  v24 = 0x10325476C3D2E1F0LL;
  v12 = (((a2 + 8) >> 6) + 1) << 6;
  v11 = 8 * a2;
  memset(s, c: 0, n: 0x140u);
  memcpy(dest: s, src: a1, n: a2);
  s[a2] = 0x80;
  for ( i = 0; i <= 7; ++i )
    s[v12 - i - 1] = v11 >> (8 * (unsigned __int8)i);
  for ( j = 0; j < v12; j += 64LL )
  {
    for ( k = 0; k <= 15; ++k )
      v7[k] = (unsigned __int8)s[4 * k + 3 + j]
            | ((unsigned __int8)s[4 * k + 2 + j] << 8)
            | ((unsigned __int8)s[4 * k + 1 + j] << 16)
            | ((unsigned __int8)s[4 * k + j] << 24);
    for ( m = 16; m <= 79; ++m )
      v7[m] = __ROL4__(v7[m - 14] ^ v7[m - 8] ^ v7[m - 3] ^ v7[m - 16], 1);
    v19 = v27;
    v18 = v26;
    v17[2] = v25;
    *(_QWORD *)v17 = v24;
    for ( ii = 0; ii <= 79; ++ii )
    {
      if ( ii > 19 )
      {
        if ( ii > 39 )
        {
          if ( ii > 59 )
          {
            v15 = v17[1] ^ v17[2] ^ v18;
            v14 = -899497514;
          }
          else
          {
            v15 = v18 & (v17[1] | v17[2]) | v17[1] & v17[2];
            v14 = -1894007588;
          }
        }
        else
        {
          v15 = v17[1] ^ v17[2] ^ v18;
          v14 = 1859775393;
        }
      }
      else
      {
        v15 = v17[2] & v18 | v17[1] & ~v18;
        v14 = 1518500249;
      }
      v10 = v14 + v17[0] + v15 + __ROL4__(v19, 5) + v7[ii];
      v17[0] = v17[1];
      v17[1] = v17[2];
      v17[2] = __ROR4__(v18, 2);
      v18 = v19;
      v19 = v10;
    }
    v27 += v19;
    v26 += v18;
    v25 += v17[2];
    HIDWORD(v24) += v17[1];
    LODWORD(v24) = v17[0] + v24;
  }
  v8[0] = v27;
  v8[1] = v26;
  v8[2] = v25;
  v8[3] = HIDWORD(v24);
  result = (unsigned int)v24;
  v8[4] = v24;
  for ( jj = 0; jj <= 4; ++jj )
  {
    *(_BYTE *)(4 * jj + a3) = HIBYTE(v8[jj]);
    *(_BYTE *)(4 * jj + 1LL + a3) = BYTE2(v8[jj]);
    *(_BYTE *)(4 * jj + 2LL + a3) = BYTE1(v8[jj]);
    result = 4 * jj + 3LL + a3;
    *(_BYTE *)result = v8[jj];
  }
  return result;
}
