__int64 __fastcall b58_encode(__int64 a1, unsigned __int64 a2, __int64 a3)
{
  __int64 v3; // rax
  __int64 v4; // rax
  int v5; // ecx
  __int64 v6; // rax
  __int64 v10; // [rsp+18h] [rbp-178h]
  _BYTE s[304]; // [rsp+20h] [rbp-170h] BYREF
  unsigned __int64 m; // [rsp+150h] [rbp-40h]
  unsigned __int64 k; // [rsp+158h] [rbp-38h]
  unsigned __int64 j; // [rsp+160h] [rbp-30h]
  int v15; // [rsp+16Ch] [rbp-24h]
  unsigned __int64 i; // [rsp+170h] [rbp-20h]
  __int64 v17; // [rsp+178h] [rbp-18h]
  unsigned __int64 v18; // [rsp+180h] [rbp-10h]
  unsigned __int64 v19; // [rsp+188h] [rbp-8h]

  v10 = a1;
  v19 = 0;
  v18 = 0;
  v17 = 0;
  memset(s, c: 0, n: 0x12Cu);
  while ( v19 < a2 && *(_BYTE *)(v10 + v19) == 0 )
    ++v19;
  for ( i = v19; i < a2; ++i )
  {
    v15 = *(unsigned __int8 *)(v10 + i);
    for ( j = 0; j < v18; ++j )
    {
      v15 += (unsigned __int8)s[j] << 8;
      s[j] = v15 % 58;
      v15 /= 58;
    }
    while ( v15 != 0 )
    {
      v3 = v18++;
      s[v3] = v15 % 58;
      v15 /= 58;
    }
  }
  for ( k = 0; k < v19; ++k )
  {
    v4 = v17++;
    *(_BYTE *)(a3 + v4) = 49;
  }
  for ( m = v18; m != 0; --m )
  {
    v5 = (unsigned __int8)s[m - 1];
    v6 = v17++;
    *(_BYTE *)(v6 + a3) = T_3[v5];
  }
  *(_BYTE *)(a3 + v17) = 0;
  return v17;
}
