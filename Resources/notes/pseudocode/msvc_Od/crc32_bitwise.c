__int64 __fastcall crc32_bitwise(const unsigned __int8 *p, unsigned __int64 n)
{
  unsigned int c; // [rsp+0h] [rbp-18h]
  int k; // [rsp+4h] [rbp-14h]
  unsigned __int64 i; // [rsp+8h] [rbp-10h]

  c = -1;
  for ( i = 0; i < n; ++i )
  {
    c ^= p[i];
    for ( k = 0; k < 8; ++k )
      c = -(c & 1) & 0xEDB88320 ^ (c >> 1);
  }
  return ~c;
}
