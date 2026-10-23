__int64 __fastcall aes128_encrypt_block(__int64 a1, __int64 a2, _QWORD *a3)
{
  char v3; // bl
  char v4; // bl
  char v5; // bl
  char v6; // bl
  char v7; // al
  __int64 result; // rax
  __int64 v9; // rdx
  _QWORD v10[2]; // [rsp+20h] [rbp-40h]
  __int64 v11; // [rsp+30h] [rbp-30h]
  __int64 v12; // [rsp+38h] [rbp-28h]
  unsigned __int8 v13; // [rsp+44h] [rbp-1Ch]
  unsigned __int8 v14; // [rsp+45h] [rbp-1Bh]
  unsigned __int8 v15; // [rsp+46h] [rbp-1Ah]
  unsigned __int8 v16; // [rsp+47h] [rbp-19h]
  int ii; // [rsp+48h] [rbp-18h]
  int n; // [rsp+4Ch] [rbp-14h]
  int m; // [rsp+50h] [rbp-10h]
  int k; // [rsp+54h] [rbp-Ch]
  int j; // [rsp+58h] [rbp-8h]
  int i; // [rsp+5Ch] [rbp-4h]

  for ( i = 0; i <= 15; ++i )
    *((_BYTE *)&v11 + i) = *(_BYTE *)(i + a1) ^ *(_BYTE *)(i + a2);
  for ( j = 1; j <= 10; ++j )
  {
    for ( k = 0; k <= 3; ++k )
    {
      for ( m = 0; m <= 3; ++m )
        *((_BYTE *)v10 + 4 * k + m) = AES_SBOX[*((unsigned __int8 *)&v11
                                               + 4 * (((unsigned __int8)k + (unsigned __int8)m) & 3)
                                               + m)];
    }
    if ( j > 9 )
    {
      v11 = v10[0];
      v12 = v10[1];
    }
    else
    {
      for ( n = 0; n <= 3; ++n )
      {
        v16 = *((_BYTE *)v10 + 4 * n);
        v15 = *((_BYTE *)v10 + 4 * n + 1);
        v14 = *((_BYTE *)v10 + 4 * n + 2);
        v13 = *((_BYTE *)v10 + 4 * n + 3);
        v3 = xt(a1: v16);
        *((_BYTE *)&v11 + 4 * n) = v13 ^ v14 ^ v3 ^ v15 ^ xt(a1: v15);
        v4 = v16 ^ xt(a1: v15);
        *((_BYTE *)&v11 + 4 * n + 1) = v13 ^ v4 ^ v14 ^ xt(a1: v14);
        v5 = v15 ^ v16;
        v6 = xt(a1: v14) ^ v5;
        *((_BYTE *)&v11 + 4 * n + 2) = v6 ^ v13 ^ xt(a1: v13);
        v7 = v14 ^ v15 ^ v16 ^ xt(a1: v16);
        *((_BYTE *)&v11 + 4 * n + 3) = v7 ^ xt(a1: v13);
      }
    }
    for ( ii = 0; ii <= 15; ++ii )
      *((_BYTE *)&v11 + ii) ^= *(_BYTE *)(16 * j + ii + a1);
  }
  result = v11;
  v9 = v12;
  *a3 = v11;
  a3[1] = v9;
  return result;
}
