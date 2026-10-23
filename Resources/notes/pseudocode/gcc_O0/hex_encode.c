unsigned __int64 __fastcall hex_encode(__int64 a1, unsigned __int64 a2, __int64 a3)
{
  unsigned __int64 i; // [rsp+20h] [rbp-8h]

  for ( i = 0; i < a2; ++i )
  {
    *(_BYTE *)(2 * i + a3) = H_2[*(_BYTE *)(a1 + i) >> 4];
    *(_BYTE *)(a3 + 2 * i + 1) = H_2[*(_BYTE *)(a1 + i) & 0xF];
  }
  *(_BYTE *)(2 * a2 + a3) = 0;
  return 2 * a2;
}
