// adler32_hash = sub_1400012A0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_1400012A0(__int64 a1, unsigned __int64 a2)
{
  unsigned int v2; // r8d
  unsigned int v3; // r9d
  unsigned __int64 i; // r10
  int v5; // eax

  v2 = 0;
  v3 = 1;
  for ( i = 0; i < a2; v2 = (v2 + v3) % 0xFFF1 )
  {
    v5 = *(unsigned __int8 *)(i + a1);
    ++i;
    v3 = (v5 + v3) % 0xFFF1;
  }
  return v3 | (v2 << 16);
}
