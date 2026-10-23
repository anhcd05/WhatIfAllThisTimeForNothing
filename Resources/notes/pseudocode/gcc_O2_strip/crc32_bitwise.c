// crc32_bitwise = sub_52D0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_52D0(unsigned __int8 *a1, __int64 a2)
{
  unsigned __int8 *v2; // rsi
  unsigned int v3; // eax
  int i; // edx

  if ( a2 == 0 )
    return 0;
  v2 = &a1[a2];
  v3 = -1;
  do
  {
    v3 ^= *a1;
    for ( i = 8; i != 0; --i )
      v3 = (v3 >> 1) ^ -(v3 & 1) & 0xEDB88320;
    ++a1;
  }
  while ( a1 != v2 );
  return ~v3;
}
