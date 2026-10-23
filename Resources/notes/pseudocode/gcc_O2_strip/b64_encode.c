// b64_encode = sub_2020 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_2020(__int64 a1, unsigned __int64 a2, _BYTE *a3)
{
  unsigned __int64 v4; // r9
  __int64 v6; // rdi
  __int64 v7; // rcx
  unsigned int v8; // eax
  unsigned int v9; // ebx
  unsigned __int64 v10; // rax
  _BYTE *v11; // rax
  int v13; // edx
  unsigned int v14; // ecx
  unsigned int v15; // eax
  __int64 v16; // rax
  unsigned int v17; // edx
  char v18; // al
  __int64 v19; // rax
  __int64 v20; // rdi

  v4 = a2;
  if ( a2 <= 2 )
  {
    v11 = a3;
    v6 = 0;
    v7 = 0;
  }
  else
  {
    v6 = 0;
    v7 = 0;
    do
    {
      v6 += 4;
      v8 = (*(unsigned __int8 *)(a1 + v7 + 1) << 8) | (*(unsigned __int8 *)(a1 + v7) << 16);
      v9 = v8 | *(unsigned __int8 *)(a1 + v7 + 2);
      *(_DWORD *)&a3[v6 - 4] = (unsigned __int8)aAbcdefghijklmn[v8 >> 18]
                             | (((unsigned __int8)aAbcdefghijklmn[(v8 >> 12) & 0x3F]
                               | (((unsigned __int8)aAbcdefghijklmn[(v9 >> 6) & 0x3F]
                                 | ((unsigned __int8)aAbcdefghijklmn[v9 & 0x3F] << 8)) << 8)) << 8);
      v10 = v7 + 5;
      v7 += 3;
    }
    while ( v10 < a2 );
    v4 = a2 - v7;
    v11 = &a3[v6];
  }
  if ( v4 == 1 )
  {
    v17 = *(unsigned __int8 *)(a1 + v7);
    *v11 = aAbcdefghijklmn[v17 >> 2];
    v18 = aAbcdefghijklmn[(16 * (_BYTE)v17) & 0x30];
    a3[v6 + 2] = 61;
    a3[v6 + 1] = v18;
    v19 = v6 + 3;
    v20 = v6 + 4;
    a3[v19] = 61;
    a3[v20] = 0;
    return v20;
  }
  else
  {
    if ( v4 == 2 )
    {
      v13 = *(unsigned __int8 *)(a1 + v7 + 1);
      v14 = *(unsigned __int8 *)(a1 + v7) << 16;
      *v11 = aAbcdefghijklmn[v14 >> 18];
      v15 = v14 | (v13 << 8);
      LOBYTE(v13) = aAbcdefghijklmn[(v15 >> 6) & 0x3F];
      LOBYTE(v15) = aAbcdefghijklmn[(v15 >> 12) & 0x3F];
      a3[v6 + 2] = v13;
      a3[v6 + 1] = v15;
      v16 = v6 + 3;
      v6 += 4;
      a3[v16] = 61;
      a3[v6] = 0;
    }
    else
    {
      *v11 = 0;
    }
    return v6;
  }
}
