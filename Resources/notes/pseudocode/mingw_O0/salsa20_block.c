__int64 __fastcall salsa20_block(__int64 a1, __int64 *a2, __int64 a3, __int64 a4)
{
  __int64 result; // rax
  unsigned int v5; // edx
  unsigned int v6; // [rsp+Ch] [rbp-94h]
  __int64 v7; // [rsp+10h] [rbp-90h]
  __int64 v8; // [rsp+18h] [rbp-88h]
  __int64 v9; // [rsp+20h] [rbp-80h]
  __int64 v10; // [rsp+28h] [rbp-78h]
  __int64 v11; // [rsp+30h] [rbp-70h]
  __int64 v12; // [rsp+38h] [rbp-68h]
  __int64 v13; // [rsp+40h] [rbp-60h]
  __int64 v14; // [rsp+48h] [rbp-58h]
  _QWORD v15[2]; // [rsp+50h] [rbp-50h]
  __int64 v16; // [rsp+60h] [rbp-40h]
  __int64 v17; // [rsp+68h] [rbp-38h]
  __int64 v18; // [rsp+70h] [rbp-30h]
  __int64 v19; // [rsp+78h] [rbp-28h]
  __int64 v20; // [rsp+80h] [rbp-20h]
  __int64 v21; // [rsp+88h] [rbp-18h]
  int k; // [rsp+94h] [rbp-Ch]
  int j; // [rsp+98h] [rbp-8h]
  int i; // [rsp+9Ch] [rbp-4h]

  LODWORD(v15[0]) = 1634760805;
  HIDWORD(v16) = 857760878;
  LODWORD(v19) = 2036477234;
  HIDWORD(v21) = 1797285236;
  for ( i = 0; i <= 3; ++i )
  {
    *((_DWORD *)v15 + i + 1) = *(_DWORD *)(4LL * i + a1);
    *((_DWORD *)&v15[5] + i + 1) = *(_DWORD *)(4LL * (i + 4) + a1);
  }
  v17 = *a2;
  v18 = a3;
  v7 = v15[0];
  v8 = v15[1];
  v9 = v16;
  v10 = v17;
  v11 = a3;
  v12 = v19;
  result = v20;
  v13 = v20;
  v14 = v21;
  for ( j = 0; j <= 9; ++j )
  {
    LODWORD(v9) = __ROL4__(v7 + v13, 7) ^ v9;
    LODWORD(v11) = __ROL4__(v9 + v7, 9) ^ v11;
    LODWORD(v13) = __ROL4__(v11 + v9, 13) ^ v13;
    LODWORD(v7) = __ROR4__(v13 + v11, 14) ^ v7;
    HIDWORD(v11) ^= __ROL4__(HIDWORD(v9) + HIDWORD(v7), 7);
    HIDWORD(v13) ^= __ROL4__(HIDWORD(v11) + HIDWORD(v9), 9);
    HIDWORD(v7) ^= __ROL4__(HIDWORD(v13) + HIDWORD(v11), 13);
    HIDWORD(v9) ^= __ROR4__(HIDWORD(v7) + HIDWORD(v13), 14);
    LODWORD(v14) = __ROL4__(v12 + v10, 7) ^ v14;
    LODWORD(v8) = __ROL4__(v14 + v12, 9) ^ v8;
    LODWORD(v10) = __ROL4__(v8 + v14, 13) ^ v10;
    LODWORD(v12) = __ROR4__(v10 + v8, 14) ^ v12;
    HIDWORD(v8) ^= __ROL4__(HIDWORD(v14) + HIDWORD(v12), 7);
    HIDWORD(v10) ^= __ROL4__(HIDWORD(v8) + HIDWORD(v14), 9);
    HIDWORD(v12) ^= __ROL4__(HIDWORD(v10) + HIDWORD(v8), 13);
    HIDWORD(v14) ^= __ROR4__(HIDWORD(v12) + HIDWORD(v10), 14);
    HIDWORD(v7) ^= __ROL4__(v7 + HIDWORD(v8), 7);
    LODWORD(v8) = __ROL4__(HIDWORD(v7) + v7, 9) ^ v8;
    HIDWORD(v8) ^= __ROL4__(v8 + HIDWORD(v7), 13);
    LODWORD(v7) = __ROR4__(HIDWORD(v8) + v8, 14) ^ v7;
    LODWORD(v10) = __ROL4__(HIDWORD(v9) + v9, 7) ^ v10;
    HIDWORD(v10) ^= __ROL4__(v10 + HIDWORD(v9), 9);
    LODWORD(v9) = __ROL4__(HIDWORD(v10) + v10, 13) ^ v9;
    HIDWORD(v9) ^= __ROR4__(v9 + HIDWORD(v10), 14);
    HIDWORD(v12) ^= __ROL4__(v12 + HIDWORD(v11), 7);
    LODWORD(v11) = __ROL4__(HIDWORD(v12) + v12, 9) ^ v11;
    HIDWORD(v11) ^= __ROL4__(v11 + HIDWORD(v12), 13);
    LODWORD(v12) = __ROR4__(HIDWORD(v11) + v11, 14) ^ v12;
    LODWORD(v13) = __ROL4__(HIDWORD(v14) + v14, 7) ^ v13;
    HIDWORD(v13) ^= __ROL4__(v13 + HIDWORD(v14), 9);
    LODWORD(v14) = __ROL4__(HIDWORD(v13) + v13, 13) ^ v14;
    v5 = __ROR4__(v14 + HIDWORD(v13), 14);
    result = v5 ^ HIDWORD(v14);
    HIDWORD(v14) ^= v5;
  }
  for ( k = 0; k <= 15; ++k )
  {
    v6 = *((_DWORD *)&v7 + k) + *((_DWORD *)v15 + k);
    result = v6;
    *(_DWORD *)(a4 + 4 * k) = v6;
  }
  return result;
}
