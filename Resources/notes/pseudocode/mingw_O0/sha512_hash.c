_BYTE *__fastcall sha512_hash(const void *a1, size_t a2, __int64 a3)
{
  _BYTE *result; // rax
  _QWORD v4[80]; // [rsp+20h] [rbp-60h]
  __int64 v5; // [rsp+2A0h] [rbp+220h]
  __int64 v6; // [rsp+2A8h] [rbp+228h]
  __int64 v7; // [rsp+2B0h] [rbp+230h]
  __int64 v8; // [rsp+2B8h] [rbp+238h]
  __int64 v9; // [rsp+2C0h] [rbp+240h]
  __int64 v10; // [rsp+2C8h] [rbp+248h]
  __int64 v11; // [rsp+2D0h] [rbp+250h]
  __int64 v12; // [rsp+2D8h] [rbp+258h]
  _BYTE v13[392]; // [rsp+2E0h] [rbp+260h] BYREF
  __int64 v14; // [rsp+468h] [rbp+3E8h]
  __int64 v15; // [rsp+470h] [rbp+3F0h]
  __int64 v16; // [rsp+478h] [rbp+3F8h]
  __int64 v17; // [rsp+480h] [rbp+400h]
  __int64 v18; // [rsp+488h] [rbp+408h]
  __int64 v19; // [rsp+490h] [rbp+410h]
  __int64 v20; // [rsp+498h] [rbp+418h]
  __int64 v21; // [rsp+4A0h] [rbp+420h]
  size_t v22; // [rsp+4A8h] [rbp+428h]
  size_t v23; // [rsp+4B0h] [rbp+430h]
  int mm; // [rsp+4BCh] [rbp+43Ch]
  int kk; // [rsp+4C0h] [rbp+440h]
  int jj; // [rsp+4C4h] [rbp+444h]
  __int64 v27; // [rsp+4C8h] [rbp+448h]
  __int64 v28; // [rsp+4D0h] [rbp+450h]
  __int64 v29; // [rsp+4D8h] [rbp+458h]
  __int64 v30; // [rsp+4E0h] [rbp+460h]
  __int64 v31; // [rsp+4E8h] [rbp+468h]
  __int64 v32; // [rsp+4F0h] [rbp+470h]
  __int64 v33; // [rsp+4F8h] [rbp+478h]
  __int64 v34; // [rsp+500h] [rbp+480h]
  int ii; // [rsp+508h] [rbp+488h]
  int n; // [rsp+50Ch] [rbp+48Ch]
  __int64 v37; // [rsp+510h] [rbp+490h]
  int m; // [rsp+51Ch] [rbp+49Ch]
  _BYTE *k; // [rsp+520h] [rbp+4A0h]
  int j; // [rsp+528h] [rbp+4A8h]
  int i; // [rsp+52Ch] [rbp+4ACh]

  v23 = (((a2 + 16) >> 7) + 1) << 7;
  v22 = 8 * a2;
  for ( i = 0; i <= 7; ++i )
    *(&v5 + i) = SHA512_H0[i];
  memset(a1: v13, Val: 0, Size: 0x180u);
  memcpy_0(a1: v13, Src: a1, Size: a2);
  v13[a2] = 0x80;
  for ( j = 0; j <= 7; ++j )
    v13[v23 - j - 1] = v22 >> (8 * (unsigned __int8)j);
  for ( k = nullptr; ; k += 128 )
  {
    result = k;
    if ( (unsigned __int64)k >= v23 )
      break;
    for ( m = 0; m <= 15; ++m )
    {
      v37 = 0;
      for ( n = 0; n <= 7; ++n )
        v37 = (v37 << 8) | (unsigned __int8)v13[(_QWORD)&k[8 * m + n]];
      v4[m] = v37;
    }
    for ( ii = 16; ii <= 79; ++ii )
    {
      v15 = __ROR8__(v4[ii - 15], 8) ^ __ROR8__(v4[ii - 15], 1) ^ (v4[ii - 15] >> 7);
      v14 = __ROL8__(v4[ii - 2], 3) ^ __ROR8__(v4[ii - 2], 19) ^ (v4[ii - 2] >> 6);
      v4[ii] = v14 + v4[ii - 7] + v15 + v4[ii - 16];
    }
    v34 = v5;
    v33 = v6;
    v32 = v7;
    v31 = v8;
    v30 = v9;
    v29 = v10;
    v28 = v11;
    v27 = v12;
    for ( jj = 0; jj <= 79; ++jj )
    {
      v21 = __ROR8__(v30, 18) ^ __ROR8__(v30, 14) ^ __ROL8__(v30, 23);
      v20 = v29 & v30 ^ v28 & ~v30;
      v19 = v21 + v27 + v20 + SHA512_K[jj] + v4[jj];
      v18 = __ROL8__(v34, 30) ^ __ROR8__(v34, 28) ^ __ROL8__(v34, 25);
      v17 = v34 & (v32 ^ v33) ^ v32 & v33;
      v16 = v18 + v17;
      v27 = v28;
      v28 = v29;
      v29 = v30;
      v30 = v31 + v19;
      v31 = v32;
      v32 = v33;
      v33 = v34;
      v34 = v19 + v18 + v17;
    }
    v5 += v34;
    v6 += v33;
    v7 += v32;
    v8 += v31;
    v9 += v30;
    v10 += v29;
    v11 += v28;
    v12 += v27;
  }
  for ( kk = 0; kk <= 7; ++kk )
  {
    for ( mm = 0; mm <= 7; ++mm )
    {
      result = (_BYTE *)(8 * kk + mm + a3);
      *result = (unsigned __int64)*(&v5 + kk) >> (8 * (7 - (unsigned __int8)mm));
    }
  }
  return result;
}
