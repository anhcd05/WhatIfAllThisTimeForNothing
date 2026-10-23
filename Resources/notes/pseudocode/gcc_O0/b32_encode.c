__int64 __fastcall b32_encode(__int64 a1, unsigned __int64 a2, __int64 a3)
{
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  unsigned __int64 i; // [rsp+18h] [rbp-20h]
  int v8; // [rsp+24h] [rbp-14h]
  unsigned __int64 v9; // [rsp+28h] [rbp-10h]
  __int64 v10; // [rsp+30h] [rbp-8h]

  v10 = 0;
  v9 = 0;
  v8 = 0;
  for ( i = 0; i < a2; ++i )
  {
    v9 = (v9 << 8) | *(unsigned __int8 *)(a1 + i);
    for ( v8 += 8; v8 > 4; *(_BYTE *)(v3 + a3) = T_4[(v9 >> v8) & 0x1F] )
    {
      v8 -= 5;
      v3 = v10++;
    }
  }
  if ( v8 > 0 )
  {
    v4 = v10++;
    *(_BYTE *)(v4 + a3) = T_4[(v9 << (5 - (unsigned __int8)v8)) & 0x1F];
  }
  while ( (v10 & 7) != 0 )
  {
    v5 = v10++;
    *(_BYTE *)(a3 + v5) = 61;
  }
  *(_BYTE *)(a3 + v10) = 0;
  return v10;
}
