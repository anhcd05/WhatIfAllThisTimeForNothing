__int64 __fastcall b58_encode(__int64 a1, unsigned __int64 a2, __int64 a3)
{
  __int64 v3; // rax
  __int64 v4; // rax
  int v5; // ecx
  __int64 v6; // rax
  _BYTE v8[304]; // [rsp+20h] [rbp-60h] BYREF
  unsigned __int64 m; // [rsp+150h] [rbp+D0h]
  unsigned __int64 k; // [rsp+158h] [rbp+D8h]
  unsigned __int64 j; // [rsp+160h] [rbp+E0h]
  int v12; // [rsp+16Ch] [rbp+ECh]
  unsigned __int64 i; // [rsp+170h] [rbp+F0h]
  __int64 v14; // [rsp+178h] [rbp+F8h]
  unsigned __int64 v15; // [rsp+180h] [rbp+100h]
  unsigned __int64 v16; // [rsp+188h] [rbp+108h]

  v16 = 0;
  v15 = 0;
  v14 = 0;
  memset(a1: v8, Val: 0, Size: 0x12Cu);
  while ( v16 < a2 && *(_BYTE *)(a1 + v16) == 0 )
    ++v16;
  for ( i = v16; i < a2; ++i )
  {
    v12 = *(unsigned __int8 *)(a1 + i);
    for ( j = 0; j < v15; ++j )
    {
      v12 += (unsigned __int8)v8[j] << 8;
      v8[j] = v12 % 58;
      v12 /= 58;
    }
    while ( v12 != 0 )
    {
      v3 = v15++;
      v8[v3] = v12 % 58;
      v12 /= 58;
    }
  }
  for ( k = 0; k < v16; ++k )
  {
    v4 = v14++;
    *(_BYTE *)(a3 + v4) = 49;
  }
  for ( m = v15; m != 0; --m )
  {
    v5 = (unsigned __int8)v8[m - 1];
    v6 = v14++;
    *(_BYTE *)(v6 + a3) = T_3[v5];
  }
  *(_BYTE *)(a3 + v14) = 0;
  return v14;
}
