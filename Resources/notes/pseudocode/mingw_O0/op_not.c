unsigned __int64 __fastcall op_not(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 result; // rax
  unsigned __int64 i; // [rsp+8h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= a2 )
      break;
    *(_BYTE *)(a1 + i) = ~*(_BYTE *)(a1 + i);
  }
  return result;
}
