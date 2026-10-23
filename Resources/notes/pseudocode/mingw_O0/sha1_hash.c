unsigned __int64 __fastcall sha1_hash(const void *a1, size_t a2, __int64 a3)
{
  unsigned __int64 result; // rax
  _DWORD v4[80]; // [rsp+20h] [rbp-60h]
  _DWORD v5[8]; // [rsp+160h] [rbp+E0h]
  _BYTE v6[332]; // [rsp+180h] [rbp+100h] BYREF
  int v7; // [rsp+2CCh] [rbp+24Ch]
  size_t v8; // [rsp+2D0h] [rbp+250h]
  size_t v9; // [rsp+2D8h] [rbp+258h]
  int ii; // [rsp+2E4h] [rbp+264h]
  int v11; // [rsp+2E8h] [rbp+268h]
  int v12; // [rsp+2ECh] [rbp+26Ch]
  int n; // [rsp+2F0h] [rbp+270h]
  _DWORD v14[3]; // [rsp+2F4h] [rbp+274h]
  int v15; // [rsp+300h] [rbp+280h]
  int v16; // [rsp+304h] [rbp+284h]
  int m; // [rsp+308h] [rbp+288h]
  int k; // [rsp+30Ch] [rbp+28Ch]
  size_t j; // [rsp+310h] [rbp+290h]
  int i; // [rsp+318h] [rbp+298h]
  __int64 v21; // [rsp+31Ch] [rbp+29Ch]
  int v22; // [rsp+324h] [rbp+2A4h]
  int v23; // [rsp+328h] [rbp+2A8h]
  int v24; // [rsp+32Ch] [rbp+2ACh]

  v24 = 1732584193;
  v23 = -271733879;
  v22 = -1732584194;
  v21 = 0x10325476C3D2E1F0LL;
  v9 = (((a2 + 8) >> 6) + 1) << 6;
  v8 = 8 * a2;
  memset(a1: v6, Val: 0, Size: 0x140u);
  memcpy_0(a1: v6, Src: a1, Size: a2);
  v6[a2] = 0x80;
  for ( i = 0; i <= 7; ++i )
    v6[v9 - i - 1] = v8 >> (8 * (unsigned __int8)i);
  for ( j = 0; j < v9; j += 64LL )
  {
    for ( k = 0; k <= 15; ++k )
      v4[k] = (unsigned __int8)v6[4 * k + 3 + j]
            | ((unsigned __int8)v6[4 * k + 2 + j] << 8)
            | ((unsigned __int8)v6[4 * k + 1 + j] << 16)
            | ((unsigned __int8)v6[4 * k + j] << 24);
    for ( m = 16; m <= 79; ++m )
      v4[m] = __ROL4__(v4[m - 14] ^ v4[m - 8] ^ v4[m - 3] ^ v4[m - 16], 1);
    v16 = v24;
    v15 = v23;
    v14[2] = v22;
    *(_QWORD *)v14 = v21;
    for ( n = 0; n <= 79; ++n )
    {
      if ( n > 19 )
      {
        if ( n > 39 )
        {
          if ( n > 59 )
          {
            v12 = v14[1] ^ v14[2] ^ v15;
            v11 = -899497514;
          }
          else
          {
            v12 = v15 & (v14[1] | v14[2]) | v14[1] & v14[2];
            v11 = -1894007588;
          }
        }
        else
        {
          v12 = v14[1] ^ v14[2] ^ v15;
          v11 = 1859775393;
        }
      }
      else
      {
        v12 = v14[2] & v15 | v14[1] & ~v15;
        v11 = 1518500249;
      }
      v7 = v11 + v14[0] + v12 + __ROL4__(v16, 5) + v4[n];
      v14[0] = v14[1];
      v14[1] = v14[2];
      v14[2] = __ROR4__(v15, 2);
      v15 = v16;
      v16 = v7;
    }
    v24 += v16;
    v23 += v15;
    v22 += v14[2];
    HIDWORD(v21) += v14[1];
    LODWORD(v21) = v14[0] + v21;
  }
  v5[0] = v24;
  v5[1] = v23;
  v5[2] = v22;
  v5[3] = HIDWORD(v21);
  result = (unsigned int)v21;
  v5[4] = v21;
  for ( ii = 0; ii <= 4; ++ii )
  {
    *(_BYTE *)(4 * ii + a3) = HIBYTE(v5[ii]);
    *(_BYTE *)(4 * ii + 1LL + a3) = BYTE2(v5[ii]);
    *(_BYTE *)(4 * ii + 2LL + a3) = BYTE1(v5[ii]);
    result = 4 * ii + 3LL + a3;
    *(_BYTE *)result = v5[ii];
  }
  return result;
}
