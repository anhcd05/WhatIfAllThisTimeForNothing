__int64 __fastcall gm(unsigned __int8 a1, unsigned __int8 a2)
{
  unsigned __int8 v5; // [rsp+17h] [rbp-1h]

  v5 = 0;
  while ( a2 != 0 )
  {
    if ( (a2 & 1) != 0 )
      v5 ^= a1;
    a1 = xt(a1);
    a2 >>= 1;
  }
  return v5;
}
