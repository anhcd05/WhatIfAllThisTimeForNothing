unsigned __int64 __fastcall hex_encode(const unsigned __int8 *in, unsigned __int64 n, char *out)
{
  unsigned __int64 i; // [rsp+0h] [rbp-18h]

  for ( i = 0; i < n; ++i )
  {
    out[2 * i] = H[(int)in[i] >> 4];
    out[2 * i + 1] = H[in[i] & 0xF];
  }
  out[2 * n] = 0;
  return 2 * n;
}
