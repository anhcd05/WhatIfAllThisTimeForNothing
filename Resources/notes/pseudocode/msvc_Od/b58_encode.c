unsigned __int64 __fastcall b58_encode(const unsigned __int8 *in, unsigned __int64 n, char *out)
{
  int carry; // [rsp+20h] [rbp-188h]
  int carrya; // [rsp+20h] [rbp-188h]
  unsigned __int64 o; // [rsp+28h] [rbp-180h]
  unsigned __int64 zeros; // [rsp+30h] [rbp-178h]
  unsigned __int64 j; // [rsp+38h] [rbp-170h]
  unsigned __int64 len; // [rsp+40h] [rbp-168h]
  unsigned __int64 i; // [rsp+48h] [rbp-160h]
  unsigned __int64 m; // [rsp+50h] [rbp-158h]
  unsigned __int64 k; // [rsp+58h] [rbp-150h]
  unsigned __int8 buf[304]; // [rsp+60h] [rbp-148h] BYREF

  zeros = 0;
  len = 0;
  o = 0;
  memset(a1: buf, Val: 0, Size: 0x12Cu);
  while ( zeros < n && in[zeros] == 0 )
    ++zeros;
  for ( i = zeros; i < n; ++i )
  {
    carry = in[i];
    for ( j = 0; j < len; ++j )
    {
      carrya = (buf[j] << 8) + carry;
      buf[j] = carrya % 58;
      carry = carrya / 58;
    }
    while ( carry != 0 )
    {
      buf[len++] = carry % 58;
      carry /= 58;
    }
  }
  for ( k = 0; k < zeros; ++k )
    out[o++] = 49;
  for ( m = len; m != 0; --m )
    out[o++] = T_2[buf[m - 1]];
  out[o] = 0;
  return o;
}
