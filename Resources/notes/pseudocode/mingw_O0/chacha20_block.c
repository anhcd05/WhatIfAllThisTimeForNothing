__int64 __fastcall chacha20_block(__int64 a1, int a2, __int64 a3, __int64 a4)
{
  __int64 result; // rax
  unsigned int v5; // [rsp+Ch] [rbp-94h]
  _QWORD v6[2]; // [rsp+10h] [rbp-90h]
  __int128 v7; // [rsp+20h] [rbp-80h]
  __int128 v8; // [rsp+30h] [rbp-70h]
  __int128 v9; // [rsp+40h] [rbp-60h]
  _QWORD v10[2]; // [rsp+50h] [rbp-50h] BYREF
  __int128 v11; // [rsp+60h] [rbp-40h]
  __int128 v12; // [rsp+70h] [rbp-30h]
  __int128 v13; // [rsp+80h] [rbp-20h]
  int k; // [rsp+94h] [rbp-Ch]
  int j; // [rsp+98h] [rbp-8h]
  int i; // [rsp+9Ch] [rbp-4h]

  v11 = 0;
  v12 = 0;
  v13 = 0;
  qmemcpy(v10, "expand 32-byte k", sizeof(v10));
  for ( i = 0; i <= 7; ++i )
    *((_DWORD *)&v10[2] + i) = *(_DWORD *)(4LL * i + a1);
  LODWORD(v13) = a2;
  *(_QWORD *)((char *)&v13 + 4) = *(_QWORD *)a3;
  HIDWORD(v13) = *(_DWORD *)(a3 + 8);
  *(_OWORD *)v6 = *(_OWORD *)v10;
  v7 = v11;
  v8 = v12;
  result = v13;
  v9 = v13;
  for ( j = 0; j <= 9; ++j )
  {
    LODWORD(v6[0]) += v7;
    LODWORD(v9) = __ROL4__(v9 ^ LODWORD(v6[0]), 16);
    LODWORD(v8) = v8 + v9;
    LODWORD(v7) = __ROL4__(v7 ^ v8, 12);
    LODWORD(v6[0]) += v7;
    LODWORD(v9) = __ROL4__(v9 ^ LODWORD(v6[0]), 8);
    LODWORD(v8) = v8 + v9;
    LODWORD(v7) = __ROL4__(v7 ^ v8, 7);
    HIDWORD(v6[0]) += DWORD1(v7);
    DWORD1(v9) = __ROL4__(DWORD1(v9) ^ HIDWORD(v6[0]), 16);
    DWORD1(v8) += DWORD1(v9);
    DWORD1(v7) = __ROL4__(DWORD1(v7) ^ DWORD1(v8), 12);
    HIDWORD(v6[0]) += DWORD1(v7);
    DWORD1(v9) = __ROL4__(DWORD1(v9) ^ HIDWORD(v6[0]), 8);
    DWORD1(v8) += DWORD1(v9);
    DWORD1(v7) = __ROL4__(DWORD1(v7) ^ DWORD1(v8), 7);
    LODWORD(v6[1]) += DWORD2(v7);
    DWORD2(v9) = __ROL4__(DWORD2(v9) ^ LODWORD(v6[1]), 16);
    DWORD2(v8) += DWORD2(v9);
    DWORD2(v7) = __ROL4__(DWORD2(v7) ^ DWORD2(v8), 12);
    LODWORD(v6[1]) += DWORD2(v7);
    DWORD2(v9) = __ROL4__(DWORD2(v9) ^ LODWORD(v6[1]), 8);
    DWORD2(v8) += DWORD2(v9);
    DWORD2(v7) = __ROL4__(DWORD2(v7) ^ DWORD2(v8), 7);
    HIDWORD(v6[1]) += HIDWORD(v7);
    HIDWORD(v9) = __ROL4__(HIDWORD(v9) ^ HIDWORD(v6[1]), 16);
    HIDWORD(v8) += HIDWORD(v9);
    HIDWORD(v7) = __ROL4__(HIDWORD(v7) ^ HIDWORD(v8), 12);
    HIDWORD(v6[1]) += HIDWORD(v7);
    HIDWORD(v9) = __ROL4__(HIDWORD(v9) ^ HIDWORD(v6[1]), 8);
    HIDWORD(v8) += HIDWORD(v9);
    HIDWORD(v7) = __ROL4__(HIDWORD(v7) ^ HIDWORD(v8), 7);
    LODWORD(v6[0]) += DWORD1(v7);
    HIDWORD(v9) = __ROL4__(HIDWORD(v9) ^ LODWORD(v6[0]), 16);
    DWORD2(v8) += HIDWORD(v9);
    DWORD1(v7) = __ROL4__(DWORD1(v7) ^ DWORD2(v8), 12);
    LODWORD(v6[0]) += DWORD1(v7);
    HIDWORD(v9) = __ROL4__(HIDWORD(v9) ^ LODWORD(v6[0]), 8);
    DWORD2(v8) += HIDWORD(v9);
    HIDWORD(v6[0]) += DWORD2(v7);
    LODWORD(v9) = __ROL4__(v9 ^ HIDWORD(v6[0]), 16);
    HIDWORD(v8) += v9;
    DWORD2(v7) = __ROL4__(DWORD2(v7) ^ HIDWORD(v8), 12);
    HIDWORD(v6[0]) += DWORD2(v7);
    LODWORD(v9) = __ROL4__(v9 ^ HIDWORD(v6[0]), 8);
    HIDWORD(v8) += v9;
    DWORD2(v7) = __ROL4__(DWORD2(v7) ^ HIDWORD(v8), 7);
    LODWORD(v6[1]) += HIDWORD(v7);
    DWORD1(v9) = __ROL4__(DWORD1(v9) ^ LODWORD(v6[1]), 16);
    LODWORD(v8) = v8 + DWORD1(v9);
    HIDWORD(v7) = __ROL4__(HIDWORD(v7) ^ v8, 12);
    LODWORD(v6[1]) += HIDWORD(v7);
    DWORD1(v9) = __ROL4__(DWORD1(v9) ^ LODWORD(v6[1]), 8);
    LODWORD(v8) = v8 + DWORD1(v9);
    HIDWORD(v7) = __ROL4__(HIDWORD(v7) ^ v8, 7);
    HIDWORD(v6[1]) += v7;
    DWORD2(v9) = __ROL4__(DWORD2(v9) ^ HIDWORD(v6[1]), 16);
    DWORD1(v8) += DWORD2(v9);
    *(_QWORD *)&v7 = __PAIR64__(__ROL4__(DWORD1(v7) ^ DWORD2(v8), 7), __ROL4__(v7 ^ DWORD1(v8), 12));
    HIDWORD(v6[1]) += v7;
    DWORD2(v9) = __ROL4__(DWORD2(v9) ^ HIDWORD(v6[1]), 8);
    DWORD1(v8) += DWORD2(v9);
    result = (unsigned int)__ROL4__(v7 ^ DWORD1(v8), 7);
    LODWORD(v7) = result;
  }
  for ( k = 0; k <= 15; ++k )
  {
    v5 = *((_DWORD *)v6 + k) + *((_DWORD *)v10 + k);
    result = v5;
    *(_DWORD *)(a4 + 4 * k) = v5;
  }
  return result;
}
