__int64 __fastcall crc32_table(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 i; // [rsp+0h] [rbp-10h]
  unsigned int v4; // [rsp+Ch] [rbp-4h]

  v4 = -1;
  for ( i = 0; i < a2; ++i )
    v4 = (v4 >> 8) ^ CRC32_TAB[(unsigned __int8)(v4 ^ *(_BYTE *)(a1 + i))];
  return ~v4;
}
