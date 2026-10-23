__int64 __fastcall aes128_decrypt_block(__int64 a1, __int64 a2, _QWORD *a3)
{
  char v3; // bl
  char v4; // bl
  char v5; // bl
  char v6; // bl
  char v7; // bl
  char v8; // bl
  char v9; // bl
  char v10; // bl
  char v11; // bl
  int v12; // ebx
  int v13; // ebx
  int v14; // ebx
  __int64 result; // rax
  __int64 v16; // rdx
  _QWORD v19[2]; // [rsp+20h] [rbp-50h]
  __int64 v20; // [rsp+30h] [rbp-40h]
  __int64 v21; // [rsp+38h] [rbp-38h]
  unsigned __int8 v22; // [rsp+44h] [rbp-2Ch]
  unsigned __int8 v23; // [rsp+45h] [rbp-2Bh]
  unsigned __int8 v24; // [rsp+46h] [rbp-2Ah]
  unsigned __int8 v25; // [rsp+47h] [rbp-29h]
  int ii; // [rsp+48h] [rbp-28h]
  int n; // [rsp+4Ch] [rbp-24h]
  int m; // [rsp+50h] [rbp-20h]
  int k; // [rsp+54h] [rbp-1Ch]
  int j; // [rsp+58h] [rbp-18h]
  int i; // [rsp+5Ch] [rbp-14h]

  for ( i = 0; i <= 15; ++i )
    *((_BYTE *)&v20 + i) = *(_BYTE *)(i + 160 + a1) ^ *(_BYTE *)(i + a2);
  for ( j = 9; j >= 0; --j )
  {
    for ( k = 0; k <= 3; ++k )
    {
      for ( m = 0; m <= 3; ++m )
        *((_BYTE *)v19 + 4 * k + m) = AES_INV_SBOX[*((unsigned __int8 *)&v20
                                                   + 4 * (((unsigned __int8)k - (unsigned __int8)m) & 3)
                                                   + m)];
    }
    for ( n = 0; n <= 15; ++n )
      *((_BYTE *)v19 + n) ^= *(_BYTE *)(16 * j + n + a1);
    if ( j <= 0 )
    {
      v20 = v19[0];
      v21 = v19[1];
    }
    else
    {
      for ( ii = 0; ii <= 3; ++ii )
      {
        v25 = *((_BYTE *)v19 + 4 * ii);
        v24 = *((_BYTE *)v19 + 4 * ii + 1);
        v23 = *((_BYTE *)v19 + 4 * ii + 2);
        v22 = *((_BYTE *)v19 + 4 * ii + 3);
        v3 = gm(a1: v25, a2: 14);
        v4 = gm(a1: v24, a2: 11) ^ v3;
        v5 = gm(a1: v23, a2: 13) ^ v4;
        *((_BYTE *)&v20 + 4 * ii) = v5 ^ gm(a1: v22, a2: 9);
        v6 = gm(a1: v25, a2: 9);
        v7 = gm(a1: v24, a2: 14) ^ v6;
        v8 = gm(a1: v23, a2: 11) ^ v7;
        *((_BYTE *)&v20 + 4 * ii + 1) = v8 ^ gm(a1: v22, a2: 13);
        v9 = gm(a1: v25, a2: 13);
        v10 = gm(a1: v24, a2: 9) ^ v9;
        v11 = gm(a1: v23, a2: 14) ^ v10;
        *((_BYTE *)&v20 + 4 * ii + 2) = v11 ^ gm(a1: v22, a2: 11);
        v12 = gm(a1: v25, a2: 11);
        v13 = gm(a1: v24, a2: 13) ^ v12;
        v14 = gm(a1: v23, a2: 9) ^ v13;
        *((_BYTE *)&v20 + 4 * ii + 3) = v14 ^ gm(a1: v22, a2: 14);
      }
    }
  }
  result = v20;
  v16 = v21;
  *a3 = v20;
  a3[1] = v16;
  return result;
}
