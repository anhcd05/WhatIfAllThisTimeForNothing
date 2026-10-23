__int64 __fastcall b64_encode(__int64 a1, unsigned __int64 a2, _BYTE *a3)
{
  unsigned __int64 v4; // rbx
  __int64 v5; // r10
  __int64 v6; // rcx
  unsigned int v7; // eax
  unsigned int v8; // edi
  unsigned __int64 v9; // rax
  _BYTE *v10; // rax
  int v12; // edx
  unsigned int v13; // ecx
  unsigned int v14; // eax
  __int64 v15; // rax
  unsigned int v16; // edx
  char v17; // al
  __int64 v18; // rax
  __int64 v19; // r10

  v4 = a2;
  if ( a2 <= 2 )
  {
    v10 = a3;
    v5 = 0;
    v6 = 0;
  }
  else
  {
    v5 = 0;
    v6 = 0;
    do
    {
      v5 += 4;
      v7 = (*(unsigned __int8 *)(a1 + v6 + 1) << 8) | (*(unsigned __int8 *)(a1 + v6) << 16);
      v8 = v7 | *(unsigned __int8 *)(a1 + v6 + 2);
      *(_DWORD *)&a3[v5 - 4] = (unsigned __int8)T_6[v7 >> 18]
                             | (((unsigned __int8)T_6[(v7 >> 12) & 0x3F]
                               | (((unsigned __int8)T_6[(v8 >> 6) & 0x3F] | ((unsigned __int8)T_6[v8 & 0x3F] << 8)) << 8)) << 8);
      v9 = v6 + 5;
      v6 += 3;
    }
    while ( v9 < a2 );
    v4 = a2 - v6;
    v10 = &a3[v5];
  }
  if ( v4 == 1 )
  {
    v16 = *(unsigned __int8 *)(a1 + v6);
    *v10 = T_6[v16 >> 2];
    v17 = T_6[(16 * (_BYTE)v16) & 0x30];
    a3[v5 + 2] = 61;
    a3[v5 + 1] = v17;
    v18 = v5 + 3;
    v19 = v5 + 4;
    a3[v18] = 61;
    a3[v19] = 0;
    return v19;
  }
  else
  {
    if ( v4 == 2 )
    {
      v12 = *(unsigned __int8 *)(a1 + v6 + 1);
      v13 = *(unsigned __int8 *)(a1 + v6) << 16;
      *v10 = T_6[v13 >> 18];
      v14 = v13 | (v12 << 8);
      LOBYTE(v12) = T_6[(v14 >> 6) & 0x3F];
      LOBYTE(v14) = T_6[(v14 >> 12) & 0x3F];
      a3[v5 + 2] = v12;
      a3[v5 + 1] = v14;
      v15 = v5 + 3;
      v5 += 4;
      a3[v15] = 61;
      a3[v5] = 0;
    }
    else
    {
      *v10 = 0;
    }
    return v5;
  }
}
