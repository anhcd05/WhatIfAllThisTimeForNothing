__int64 __fastcall gm(unsigned __int8 a, unsigned __int8 b)
{
  unsigned __int8 v2; // bl
  unsigned __int8 v3; // r11
  unsigned __int8 v4; // r8
  unsigned __int8 v5; // r10

  v2 = 0;
  v3 = b;
  if ( b != 0 )
  {
    do
    {
      v4 = a ^ v2;
      v5 = v3;
      if ( (v3 & 1) == 0 )
        v4 = v2;
      v2 = v4;
      v3 >>= 1;
      a = (27 * (a >> 7)) ^ (2 * a);
    }
    while ( v5 >= 2u );
  }
  return v2;
}
