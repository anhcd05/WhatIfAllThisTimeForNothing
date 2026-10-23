// crc32_table = sub_1400029A0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_1400029A0(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v2; // r10
  unsigned int i; // eax
  unsigned __int8 v4; // r9

  v2 = 0;
  for ( i = -1; v2 < a2; i = (i >> 8) ^ dword_1400184D0[v4] )
  {
    v4 = i ^ *(_BYTE *)(v2 + a1);
    ++v2;
  }
  return ~i;
}
