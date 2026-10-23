__int64 __fastcall aes128_encrypt_block(__int64 a1, __int64 a2, _QWORD *a3)
{
  char v3; // bl
  char v4; // bl
  char v5; // bl
  char v6; // bl
  char v7; // al
  __int64 result; // rax
  __int64 v9; // rdx
  _QWORD v12[2]; // [rsp+20h] [rbp-50h]
  __int64 v13; // [rsp+30h] [rbp-40h]
  __int64 v14; // [rsp+38h] [rbp-38h]
  unsigned __int8 v15; // [rsp+44h] [rbp-2Ch]
  unsigned __int8 v16; // [rsp+45h] [rbp-2Bh]
  unsigned __int8 v17; // [rsp+46h] [rbp-2Ah]
  unsigned __int8 v18; // [rsp+47h] [rbp-29h]
  int ii; // [rsp+48h] [rbp-28h]
  int n; // [rsp+4Ch] [rbp-24h]
  int m; // [rsp+50h] [rbp-20h]
  int k; // [rsp+54h] [rbp-1Ch]
  int j; // [rsp+58h] [rbp-18h]
  int i; // [rsp+5Ch] [rbp-14h]

  for ( i = 0; i <= 15; ++i )
    *((_BYTE *)&v13 + i) = *(_BYTE *)(i + a1) ^ *(_BYTE *)(i + a2);
  for ( j = 1; j <= 10; ++j )
  {
    for ( k = 0; k <= 3; ++k )
    {
      for ( m = 0; m <= 3; ++m )
        *((_BYTE *)v12 + 4 * k + m) = AES_SBOX[*((unsigned __int8 *)&v13
                                               + 4 * (((unsigned __int8)k + (unsigned __int8)m) & 3)
                                               + m)];
    }
    if ( j > 9 )
    {
      v13 = v12[0];
      v14 = v12[1];
    }
    else
    {
      for ( n = 0; n <= 3; ++n )
      {
        v18 = *((_BYTE *)v12 + 4 * n);
        v17 = *((_BYTE *)v12 + 4 * n + 1);
        v16 = *((_BYTE *)v12 + 4 * n + 2);
        v15 = *((_BYTE *)v12 + 4 * n + 3);
        v3 = xt(a1: v18);
        *((_BYTE *)&v13 + 4 * n) = v15 ^ v16 ^ v3 ^ v17 ^ xt(a1: v17);
        v4 = v18 ^ xt(a1: v17);
        *((_BYTE *)&v13 + 4 * n + 1) = v15 ^ v4 ^ v16 ^ xt(a1: v16);
        v5 = v17 ^ v18;
        v6 = xt(a1: v16) ^ v5;
        *((_BYTE *)&v13 + 4 * n + 2) = v6 ^ v15 ^ xt(a1: v15);
        v7 = v16 ^ v17 ^ v18 ^ xt(a1: v18);
        *((_BYTE *)&v13 + 4 * n + 3) = v7 ^ xt(a1: v15);
      }
    }
    for ( ii = 0; ii <= 15; ++ii )
      *((_BYTE *)&v13 + ii) ^= *(_BYTE *)(16 * j + ii + a1);
  }
  result = v13;
  v9 = v14;
  *a3 = v13;
  a3[1] = v9;
  return result;
}
