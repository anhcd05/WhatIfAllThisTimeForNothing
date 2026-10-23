__int64 __fastcall crc32_table(const unsigned __int8 *p, unsigned __int64 n)
{
  unsigned int c; // [rsp+0h] [rbp-18h]
  unsigned __int64 i; // [rsp+8h] [rbp-10h]

  c = -1;
  for ( i = 0; i < n; ++i )
    c = (c >> 8) ^ CRC32_TAB[(unsigned __int8)(p[i] ^ c)];
  return ~c;
}
