// tea_encrypt = sub_1400024F0 (bản strip, IDA không có tên hàm)
__int64 __fastcall sub_1400024F0(unsigned int *a1, int *a2)
{
  int v2; // r8d
  unsigned int v5; // ecx
  unsigned int v6; // edx
  int v7; // esi
  int v8; // r11d
  int v9; // r10d
  int v10; // r9d
  __int64 result; // rax

  v2 = 0;
  v5 = *a1;
  v6 = a1[1];
  v7 = *a2;
  v8 = a2[1];
  v9 = a2[2];
  v10 = a2[3];
  do
  {
    v2 -= 1640531527;
    v5 += (v2 + v6) ^ (v8 + (v6 >> 5)) ^ (v7 + 16 * v6);
    result = (v2 + v5) ^ (v10 + (v5 >> 5)) ^ (v9 + 16 * v5);
    v6 += result;
  }
  while ( v2 != -957401312 );
  *a1 = v5;
  a1[1] = v6;
  return result;
}
