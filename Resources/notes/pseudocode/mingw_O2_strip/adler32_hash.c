// adler32_hash = sub_140004BB0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_140004BB0(unsigned __int8 *a1, __int64 a2)
{
  unsigned __int8 *v2; // rdx
  unsigned int v3; // eax
  unsigned int v4; // r8d
  int v5; // r9d

  if ( a2 == 0 )
    return 1;
  v2 = &a1[a2];
  v3 = 0;
  v4 = 1;
  do
  {
    v5 = *a1++;
    v4 = (v5 + v4) % 0xFFF1;
    v3 = (v4 + v3) % 0xFFF1;
  }
  while ( v2 != a1 );
  return v4 | (v3 << 16);
}
