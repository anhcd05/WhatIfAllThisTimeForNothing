// tea_decrypt = sub_2F50 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_2F50(unsigned int *a1, int *a2)
{
  unsigned int v3; // ecx
  unsigned int v4; // edx
  int v5; // r11d
  int v6; // r9d
  int v7; // r8d
  int v8; // edi
  int i; // esi
  __int64 result; // rax

  v3 = *a1;
  v4 = a1[1];
  v5 = a2[2];
  v6 = a2[3];
  v7 = *a2;
  v8 = a2[1];
  for ( i = -957401312; i != 0; i += 1640531527 )
  {
    v4 -= (v3 + i) ^ (v6 + (v3 >> 5)) ^ (v5 + 16 * v3);
    result = (v4 + i) ^ (v8 + (v4 >> 5)) ^ (v7 + 16 * v4);
    v3 -= result;
  }
  *a1 = v3;
  a1[1] = v4;
  return result;
}
