_BYTE *__fastcall sha512_hash(const void *a1, size_t a2, __int64 a3)
{
  _BYTE *result; // rax
  _QWORD v7[80]; // [rsp+20h] [rbp-510h]
  __int64 v8; // [rsp+2A0h] [rbp-290h]
  __int64 v9; // [rsp+2A8h] [rbp-288h]
  __int64 v10; // [rsp+2B0h] [rbp-280h]
  __int64 v11; // [rsp+2B8h] [rbp-278h]
  __int64 v12; // [rsp+2C0h] [rbp-270h]
  __int64 v13; // [rsp+2C8h] [rbp-268h]
  __int64 v14; // [rsp+2D0h] [rbp-260h]
  __int64 v15; // [rsp+2D8h] [rbp-258h]
  _BYTE s[392]; // [rsp+2E0h] [rbp-250h] BYREF
  __int64 v17; // [rsp+468h] [rbp-C8h]
  __int64 v18; // [rsp+470h] [rbp-C0h]
  __int64 v19; // [rsp+478h] [rbp-B8h]
  __int64 v20; // [rsp+480h] [rbp-B0h]
  __int64 v21; // [rsp+488h] [rbp-A8h]
  __int64 v22; // [rsp+490h] [rbp-A0h]
  __int64 v23; // [rsp+498h] [rbp-98h]
  __int64 v24; // [rsp+4A0h] [rbp-90h]
  size_t v25; // [rsp+4A8h] [rbp-88h]
  size_t v26; // [rsp+4B0h] [rbp-80h]
  int nn; // [rsp+4BCh] [rbp-74h]
  int mm; // [rsp+4C0h] [rbp-70h]
  int kk; // [rsp+4C4h] [rbp-6Ch]
  __int64 v30; // [rsp+4C8h] [rbp-68h]
  __int64 v31; // [rsp+4D0h] [rbp-60h]
  __int64 v32; // [rsp+4D8h] [rbp-58h]
  __int64 v33; // [rsp+4E0h] [rbp-50h]
  __int64 v34; // [rsp+4E8h] [rbp-48h]
  __int64 v35; // [rsp+4F0h] [rbp-40h]
  __int64 v36; // [rsp+4F8h] [rbp-38h]
  __int64 v37; // [rsp+500h] [rbp-30h]
  int jj; // [rsp+508h] [rbp-28h]
  int ii; // [rsp+50Ch] [rbp-24h]
  __int64 v40; // [rsp+510h] [rbp-20h]
  int m; // [rsp+51Ch] [rbp-14h]
  _BYTE *k; // [rsp+520h] [rbp-10h]
  int j; // [rsp+528h] [rbp-8h]
  int i; // [rsp+52Ch] [rbp-4h]

  v26 = (((a2 + 16) >> 7) + 1) << 7;
  v25 = 8 * a2;
  for ( i = 0; i <= 7; ++i )
    *(&v8 + i) = SHA512_H0[i];
  memset(s, c: 0, n: 0x180u);
  memcpy(dest: s, src: a1, n: a2);
  s[a2] = 0x80;
  for ( j = 0; j <= 7; ++j )
    s[v26 - j - 1] = v25 >> (8 * (unsigned __int8)j);
  for ( k = nullptr; ; k += 128 )
  {
    result = k;
    if ( (unsigned __int64)k >= v26 )
      break;
    for ( m = 0; m <= 15; ++m )
    {
      v40 = 0;
      for ( ii = 0; ii <= 7; ++ii )
        v40 = (v40 << 8) | (unsigned __int8)s[(_QWORD)&k[8 * m + ii]];
      v7[m] = v40;
    }
    for ( jj = 16; jj <= 79; ++jj )
    {
      v18 = __ROR8__(v7[jj - 15], 8) ^ __ROR8__(v7[jj - 15], 1) ^ (v7[jj - 15] >> 7);
      v17 = __ROL8__(v7[jj - 2], 3) ^ __ROR8__(v7[jj - 2], 19) ^ (v7[jj - 2] >> 6);
      v7[jj] = v17 + v7[jj - 7] + v18 + v7[jj - 16];
    }
    v37 = v8;
    v36 = v9;
    v35 = v10;
    v34 = v11;
    v33 = v12;
    v32 = v13;
    v31 = v14;
    v30 = v15;
    for ( kk = 0; kk <= 79; ++kk )
    {
      v24 = __ROR8__(v33, 18) ^ __ROR8__(v33, 14) ^ __ROL8__(v33, 23);
      v23 = v32 & v33 ^ v31 & ~v33;
      v22 = v24 + v30 + v23 + SHA512_K[kk] + v7[kk];
      v21 = __ROL8__(v37, 30) ^ __ROR8__(v37, 28) ^ __ROL8__(v37, 25);
      v20 = v37 & (v35 ^ v36) ^ v35 & v36;
      v19 = v21 + v20;
      v30 = v31;
      v31 = v32;
      v32 = v33;
      v33 = v34 + v22;
      v34 = v35;
      v35 = v36;
      v36 = v37;
      v37 = v22 + v21 + v20;
    }
    v8 += v37;
    v9 += v36;
    v10 += v35;
    v11 += v34;
    v12 += v33;
    v13 += v32;
    v14 += v31;
    v15 += v30;
  }
  for ( mm = 0; mm <= 7; ++mm )
  {
    for ( nn = 0; nn <= 7; ++nn )
    {
      result = (_BYTE *)(8 * mm + nn + a3);
      *result = (unsigned __int64)*(&v8 + mm) >> (8 * (7 - (unsigned __int8)nn));
    }
  }
  return result;
}
