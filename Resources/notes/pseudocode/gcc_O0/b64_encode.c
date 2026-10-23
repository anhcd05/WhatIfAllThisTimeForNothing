__int64 __fastcall b64_encode(__int64 a1, unsigned __int64 a2, __int64 a3)
{
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  unsigned int v7; // [rsp+1Ch] [rbp-1Ch]
  unsigned int v8; // [rsp+20h] [rbp-18h]
  unsigned int v9; // [rsp+24h] [rbp-14h]
  __int64 v10; // [rsp+28h] [rbp-10h]
  __int64 v11; // [rsp+30h] [rbp-8h]

  v11 = 0;
  v10 = 0;
  while ( v11 + 2 < a2 )
  {
    v7 = (*(unsigned __int8 *)(v11 + 1 + a1) << 8)
       | (*(unsigned __int8 *)(a1 + v11) << 16)
       | *(unsigned __int8 *)(v11 + 2 + a1);
    *(_BYTE *)(v10 + a3) = T_6[(unsigned int)((*(unsigned __int8 *)(v11 + 1 + a1) << 8)
                                            | (*(unsigned __int8 *)(a1 + v11) << 16)) >> 18];
    *(_BYTE *)(v10 + 1 + a3) = T_6[(v7 >> 12) & 0x3F];
    *(_BYTE *)(v10 + 2 + a3) = T_6[(v7 >> 6) & 0x3F];
    v3 = v10 + 3;
    v10 += 4;
    *(_BYTE *)(v3 + a3) = T_6[v7 & 0x3F];
    v11 += 3;
  }
  if ( a2 - v11 == 1 )
  {
    v8 = *(unsigned __int8 *)(a1 + v11) << 16;
    *(_BYTE *)(v10 + a3) = T_6[*(unsigned __int8 *)(a1 + v11) >> 2];
    *(_BYTE *)(v10 + 1 + a3) = T_6[(v8 >> 12) & 0x3F];
    *(_BYTE *)(a3 + v10 + 2) = 61;
    v4 = v10 + 3;
    v10 += 4;
    *(_BYTE *)(a3 + v4) = 61;
  }
  else if ( a2 - v11 == 2 )
  {
    v9 = (*(unsigned __int8 *)(a1 + v11) << 16) | (*(unsigned __int8 *)(v11 + 1 + a1) << 8);
    *(_BYTE *)(v10 + a3) = T_6[v9 >> 18];
    *(_BYTE *)(v10 + 1 + a3) = T_6[(v9 >> 12) & 0x3F];
    *(_BYTE *)(v10 + 2 + a3) = T_6[(v9 >> 6) & 0x3F];
    v5 = v10 + 3;
    v10 += 4;
    *(_BYTE *)(a3 + v5) = 61;
  }
  *(_BYTE *)(a3 + v10) = 0;
  return v10;
}
