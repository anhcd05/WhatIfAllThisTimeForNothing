__int64 __fastcall hex_encode(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 i; // rax

  if ( a2 != 0 )
  {
    for ( i = 0; i != a2; ++i )
    {
      *(_BYTE *)(a3 + 2 * i) = H_2[*(_BYTE *)(a1 + i) >> 4];
      *(_BYTE *)(a3 + 2 * i + 1) = H_2[*(_BYTE *)(a1 + i) & 0xF];
    }
  }
  *(_BYTE *)(a3 + 2 * a2) = 0;
  return 2 * a2;
}
