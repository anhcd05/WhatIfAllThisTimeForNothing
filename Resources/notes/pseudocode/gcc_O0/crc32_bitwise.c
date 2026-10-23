__int64 __fastcall crc32_bitwise(__int64 a1, unsigned __int64 a2)
{
  int j; // [rsp+1Ch] [rbp-14h]
  unsigned __int64 i; // [rsp+20h] [rbp-10h]
  unsigned int v5; // [rsp+2Ch] [rbp-4h]

  v5 = -1;
  for ( i = 0; i < a2; ++i )
  {
    v5 ^= *(unsigned __int8 *)(a1 + i);
    for ( j = 0; j <= 7; ++j )
      v5 = (v5 >> 1) ^ -(v5 & 1) & 0xEDB88320;
  }
  return ~v5;
}
