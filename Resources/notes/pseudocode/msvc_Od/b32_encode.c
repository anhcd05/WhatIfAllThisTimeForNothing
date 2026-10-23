unsigned __int64 __fastcall b32_encode(const unsigned __int8 *in, unsigned __int64 n, char *out)
{
  int bits; // [rsp+0h] [rbp-28h]
  unsigned __int64 o; // [rsp+8h] [rbp-20h]
  unsigned __int64 i; // [rsp+10h] [rbp-18h]
  unsigned __int64 acc; // [rsp+18h] [rbp-10h]

  o = 0;
  acc = 0;
  bits = 0;
  for ( i = 0; i < n; ++i )
  {
    acc = in[i] | (acc << 8);
    for ( bits += 8; bits >= 5; out[o++] = T_1[(acc >> bits) & 0x1F] )
      bits -= 5;
  }
  if ( bits > 0 )
    out[o++] = T_1[(acc << (5 - (unsigned __int8)bits)) & 0x1F];
  while ( o % 8 != 0 )
    out[o++] = 61;
  out[o] = 0;
  return o;
}
