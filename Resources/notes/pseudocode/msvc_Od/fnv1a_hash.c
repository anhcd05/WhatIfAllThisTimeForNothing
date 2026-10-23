__int64 __fastcall fnv1a_hash(const unsigned __int8 *p, unsigned __int64 n)
{
  unsigned int h; // [rsp+0h] [rbp-18h]
  unsigned __int64 i; // [rsp+8h] [rbp-10h]

  h = -2128831035;
  for ( i = 0; i < n; ++i )
    h = 16777619 * (p[i] ^ h);
  return h;
}
