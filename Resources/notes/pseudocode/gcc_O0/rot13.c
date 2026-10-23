unsigned __int64 __fastcall rot13(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 result; // rax
  char v3; // [rsp+17h] [rbp-9h]
  unsigned __int64 i; // [rsp+18h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= a2 )
      break;
    v3 = *(_BYTE *)(a1 + i);
    if ( v3 <= 96 || v3 > 122 )
    {
      if ( v3 > 64 && v3 <= 90 )
        *(_BYTE *)(a1 + i) = (v3 - 52) % 26 + 65;
    }
    else
    {
      *(_BYTE *)(a1 + i) = (v3 - 84) % 26 + 97;
    }
  }
  return result;
}
