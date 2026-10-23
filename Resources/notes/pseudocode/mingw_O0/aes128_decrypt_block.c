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
  _QWORD v17[2]; // [rsp+20h] [rbp-40h]
  __int64 v18; // [rsp+30h] [rbp-30h]
  __int64 v19; // [rsp+38h] [rbp-28h]
  unsigned __int8 v20; // [rsp+44h] [rbp-1Ch]
  unsigned __int8 v21; // [rsp+45h] [rbp-1Bh]
  unsigned __int8 v22; // [rsp+46h] [rbp-1Ah]
  unsigned __int8 v23; // [rsp+47h] [rbp-19h]
  int ii; // [rsp+48h] [rbp-18h]
  int n; // [rsp+4Ch] [rbp-14h]
  int m; // [rsp+50h] [rbp-10h]
  int k; // [rsp+54h] [rbp-Ch]
  int j; // [rsp+58h] [rbp-8h]
  int i; // [rsp+5Ch] [rbp-4h]

  for ( i = 0; i <= 15; ++i )
    *((_BYTE *)&v18 + i) = *(_BYTE *)(i + 160 + a1) ^ *(_BYTE *)(i + a2);
  for ( j = 9; j >= 0; --j )
  {
    for ( k = 0; k <= 3; ++k )
    {
      for ( m = 0; m <= 3; ++m )
        *((_BYTE *)v17 + 4 * k + m) = AES_INV_SBOX[*((unsigned __int8 *)&v18
                                                   + 4 * (((unsigned __int8)k - (unsigned __int8)m) & 3)
                                                   + m)];
    }
    for ( n = 0; n <= 15; ++n )
      *((_BYTE *)v17 + n) ^= *(_BYTE *)(16 * j + n + a1);
    if ( j <= 0 )
    {
      v18 = v17[0];
      v19 = v17[1];
    }
    else
    {
      for ( ii = 0; ii <= 3; ++ii )
      {
        v23 = *((_BYTE *)v17 + 4 * ii);
        v22 = *((_BYTE *)v17 + 4 * ii + 1);
        v21 = *((_BYTE *)v17 + 4 * ii + 2);
        v20 = *((_BYTE *)v17 + 4 * ii + 3);
        v3 = gm(a1: v23, a2: 14);
        v4 = gm(a1: v22, a2: 11) ^ v3;
        v5 = gm(a1: v21, a2: 13) ^ v4;
        *((_BYTE *)&v18 + 4 * ii) = v5 ^ gm(a1: v20, a2: 9);
        v6 = gm(a1: v23, a2: 9);
        v7 = gm(a1: v22, a2: 14) ^ v6;
        v8 = gm(a1: v21, a2: 11) ^ v7;
        *((_BYTE *)&v18 + 4 * ii + 1) = v8 ^ gm(a1: v20, a2: 13);
        v9 = gm(a1: v23, a2: 13);
        v10 = gm(a1: v22, a2: 9) ^ v9;
        v11 = gm(a1: v21, a2: 14) ^ v10;
        *((_BYTE *)&v18 + 4 * ii + 2) = v11 ^ gm(a1: v20, a2: 11);
        v12 = gm(a1: v23, a2: 11);
        v13 = gm(a1: v22, a2: 13) ^ v12;
        v14 = gm(a1: v21, a2: 9) ^ v13;
        *((_BYTE *)&v18 + 4 * ii + 3) = v14 ^ gm(a1: v20, a2: 14);
      }
    }
  }
  result = v18;
  v16 = v19;
  *a3 = v18;
  a3[1] = v16;
  return result;
}
