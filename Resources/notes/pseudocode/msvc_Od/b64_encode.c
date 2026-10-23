unsigned __int64 __fastcall b64_encode(const unsigned __int8 *in, unsigned __int64 n, char *out)
{
  unsigned int v; // [rsp+0h] [rbp-28h]
  unsigned int v5; // [rsp+4h] [rbp-24h]
  unsigned int v6; // [rsp+8h] [rbp-20h]
  unsigned __int64 o; // [rsp+10h] [rbp-18h]
  unsigned __int64 oa; // [rsp+10h] [rbp-18h]
  unsigned __int64 ob; // [rsp+10h] [rbp-18h]
  unsigned __int64 oc; // [rsp+10h] [rbp-18h]
  unsigned __int64 i; // [rsp+18h] [rbp-10h]

  i = 0;
  o = 0;
  while ( i + 2 < n )
  {
    v = in[i + 2] | (in[i + 1] << 8) | (in[i] << 16);
    out[o] = T[(unsigned int)((in[i + 1] << 8) | (in[i] << 16)) >> 18];
    oa = o + 1;
    out[oa] = T[(v >> 12) & 0x3F];
    out[++oa] = T[(v >> 6) & 0x3F];
    out[++oa] = T[v & 0x3F];
    o = oa + 1;
    i += 3LL;
  }
  if ( n - i == 1 )
  {
    v6 = in[i] << 16;
    out[o] = T[in[i] >> 2];
    ob = o + 1;
    out[ob] = T[(v6 >> 12) & 0x3F];
    out[++ob] = 61;
    out[++ob] = 61;
    o = ob + 1;
  }
  else if ( n - i == 2 )
  {
    v5 = (in[i + 1] << 8) | (in[i] << 16);
    out[o] = T[v5 >> 18];
    oc = o + 1;
    out[oc] = T[(v5 >> 12) & 0x3F];
    out[++oc] = T[(v5 >> 6) & 0x3F];
    out[++oc] = 61;
    o = oc + 1;
  }
  out[o] = 0;
  return o;
}
