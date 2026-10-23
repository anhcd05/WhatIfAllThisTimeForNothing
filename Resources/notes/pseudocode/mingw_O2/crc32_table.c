__int64 __fastcall crc32_table(char *a1, __int64 a2)
{
  char *v2; // rdx
  unsigned int v3; // eax
  char v4; // r8

  if ( a2 == 0 )
    return 0;
  v2 = &a1[a2];
  v3 = -1;
  do
  {
    v4 = *a1++;
    v3 = CRC32_TAB[(unsigned __int8)(v3 ^ v4)] ^ (v3 >> 8);
  }
  while ( v2 != a1 );
  return ~v3;
}
