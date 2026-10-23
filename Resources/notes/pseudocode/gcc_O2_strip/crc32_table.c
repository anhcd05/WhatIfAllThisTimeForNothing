// crc32_table = sub_5280 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_5280(char *a1, __int64 a2)
{
  char *v2; // rsi
  unsigned int v3; // eax
  char v4; // dl

  if ( a2 == 0 )
    return 0;
  v2 = &a1[a2];
  v3 = -1;
  do
  {
    v4 = *a1++;
    v3 = dword_68C0[(unsigned __int8)(v3 ^ v4)] ^ (v3 >> 8);
  }
  while ( v2 != a1 );
  return ~v3;
}
