// crc32_bitwise = sub_1400028D0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_1400028D0(__int64 a1, unsigned __int64 a2)
{
  unsigned __int64 v2; // r9
  unsigned int i; // eax
  int v4; // r8d
  unsigned int v5; // r8d
  char v6; // al
  unsigned int v7; // eax
  unsigned int v8; // eax

  v2 = 0;
  for ( i = -1;
        v2 < a2;
        i = (((v8 >> 1) ^ -(v8 & 1) & 0xEDB88320) >> 1)
          ^ -(((unsigned __int8)(v8 >> 1) ^ -(v8 & 1) & 0x20) & 1)
          & 0xEDB88320 )
  {
    v4 = *(unsigned __int8 *)(v2 + a1);
    ++v2;
    v5 = ((v4 ^ i) >> 1) ^ -(((unsigned __int8)v4 ^ (unsigned __int8)i) & 1) & 0xEDB88320;
    v6 = v5;
    v5 >>= 1;
    v7 = ((((v5 ^ -(v6 & 1) & 0xEDB88320) >> 1) ^ -(((unsigned __int8)v5 ^ -(v6 & 1) & 0x20) & 1) & 0xEDB88320) >> 1)
       ^ -(((unsigned __int8)((v5 ^ -(v6 & 1) & 0xEDB88320) >> 1)
          ^ -(((unsigned __int8)v5 ^ -(v6 & 1) & 0x20) & 1)
          & 0x20)
         & 1)
       & 0xEDB88320;
    v8 = (((v7 >> 1) ^ -(v7 & 1) & 0xEDB88320) >> 1)
       ^ -(((unsigned __int8)(v7 >> 1) ^ -(v7 & 1) & 0x20) & 1)
       & 0xEDB88320;
  }
  return ~i;
}
