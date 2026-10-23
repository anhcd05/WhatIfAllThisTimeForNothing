// crc32_table = sub_140004B00 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140004B00(char *a1, __int64 a2)
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
    v3 = dword_14000F8E0[(unsigned __int8)(v3 ^ v4)] ^ (v3 >> 8);
  }
  while ( v2 != a1 );
  return ~v3;
}
