unsigned __int64 __fastcall op_reverse(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 result; // rax
  char v3; // [rsp+17h] [rbp-9h]
  unsigned __int64 i; // [rsp+18h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    result = a2 >> 1;
    if ( i >= a2 >> 1 )
      break;
    v3 = *(_BYTE *)(a1 + i);
    *(_BYTE *)(a1 + i) = *(_BYTE *)(a2 - i - 1 + a1);
    *(_BYTE *)(a1 + a2 - i - 1) = v3;
  }
  return result;
}
