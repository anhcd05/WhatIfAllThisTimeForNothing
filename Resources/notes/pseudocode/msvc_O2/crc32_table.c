__int64 __fastcall crc32_table(const unsigned __int8 *p, unsigned __int64 n)
{
  unsigned __int64 v2; // r10
  unsigned int i; // eax
  unsigned __int8 v4; // r9

  v2 = 0;
  for ( i = -1; v2 < n; i = (i >> 8) ^ CRC32_TAB[v4] )
    v4 = i ^ p[v2++];
  return ~i;
}
