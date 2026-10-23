unsigned __int64 __fastcall mix_chain(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 result; // rax
  unsigned __int64 i; // [rsp+20h] [rbp-10h]
  char v4; // [rsp+2Fh] [rbp-1h]

  v4 = 66;
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= a2 )
      break;
    v4 ^= ((8 * ((i + 90) ^ *(_BYTE *)(a1 + i))) | ((unsigned __int8)((i + 90) ^ *(_BYTE *)(a1 + i)) >> 5)) + 19;
    *(_BYTE *)(i + a1) = v4;
  }
  return result;
}
