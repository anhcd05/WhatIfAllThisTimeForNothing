__int64 __fastcall gm(unsigned __int8 a, unsigned __int8 b)
{
  unsigned __int8 p; // [rsp+20h] [rbp-18h]

  p = 0;
  while ( b != 0 )
  {
    if ( (b & 1) != 0 )
      p ^= a;
    a = xt(x: a);
    b >>= 1;
  }
  return p;
}
