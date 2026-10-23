unsigned __int64 __fastcall b32_encode(const unsigned __int8 *in, unsigned __int64 n, char *out)
{
  unsigned __int64 result; // rax
  unsigned __int64 i; // r10
  int v5; // r9d
  unsigned __int64 v6; // r11

  result = 0;
  i = 0;
  v5 = 0;
  v6 = 0;
  if ( n != 0 )
  {
    do
    {
      v5 += 8;
      for ( i = in[v6] | (i << 8); v5 >= 5; ++result )
      {
        v5 -= 5;
        out[result] = T_1[(i >> v5) & 0x1F];
      }
      ++v6;
    }
    while ( v6 < n );
    if ( v5 > 0 )
      out[result++] = T_1[(i << (5 - (unsigned __int8)v5)) & 0x1F];
  }
  for ( ; (result & 7) != 0; ++result )
    out[result] = 61;
  out[result] = 0;
  return result;
}
