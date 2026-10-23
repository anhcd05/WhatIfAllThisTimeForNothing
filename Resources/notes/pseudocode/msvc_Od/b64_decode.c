unsigned __int64 __fastcall b64_decode(const char *in, unsigned __int8 *out)
{
  int bits; // [rsp+20h] [rbp-28h]
  unsigned int acc; // [rsp+24h] [rbp-24h]
  unsigned __int64 o; // [rsp+28h] [rbp-20h]
  const char *p; // [rsp+30h] [rbp-18h]

  acc = 0;
  bits = 0;
  o = 0;
  while ( *in != 0 && *in != 61 )
  {
    p = strchr(string: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", ch: *in);
    if ( p != nullptr )
    {
      acc = (p - "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") | (acc << 6);
      bits += 6;
      if ( bits >= 8 )
      {
        bits -= 8;
        out[o++] = acc >> bits;
      }
    }
    ++in;
  }
  return o;
}
