__int64 __fastcall djb2_hash(const unsigned __int8 *p, unsigned __int64 n)
{
  unsigned int h; // [rsp+0h] [rbp-18h]
  unsigned __int64 i; // [rsp+8h] [rbp-10h]

  h = 5381;
  for ( i = 0; i < n; ++i )
    h = p[i] + 33 * h;
  return h;
}
